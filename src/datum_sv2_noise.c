/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of CONVOY's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://convoy.xyz
 *
 * ---
 *
 * Copyright (c) 2026 Justin Reusnow and individual contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

// Stratum V2 Noise handshake and transport encryption

#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <sodium.h>

#include "datum_sv2_noise.h"
#include "datum_utils.h"

static const char noise_protocol_name[] = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256";

static secp256k1_context *secp_ctx = NULL;
static pthread_once_t secp_once = PTHREAD_ONCE_INIT;

static void datum_sv2_noise_init_once(void) {
	unsigned char seed[32];
	secp256k1_context *ctx;

	if (sodium_init() < 0) return;
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (!ctx) return;
	randombytes_buf(seed, sizeof(seed));
	if (!secp256k1_context_randomize(ctx, seed)) {
		secp256k1_context_destroy(ctx);
		return;
	}
	sodium_memzero(seed, sizeof(seed));
	secp_ctx = ctx;
}

bool datum_sv2_noise_init(void) {
	pthread_once(&secp_once, datum_sv2_noise_init_once);
	return secp_ctx != NULL;
}

// --- Noise symmetric state ---

typedef struct {
	unsigned char h[32];
	unsigned char ck[32];
	T_DATUM_SV2_CIPHER c;
} T_NOISE_SYM;

static void sym_init(T_NOISE_SYM *s) {
	// protocol name is longer than HASHLEN, so h = HASH(name); ck = h; then
	// h = HASH(h) mixes the (empty) prologue
	crypto_hash_sha256(s->h, (const unsigned char *)noise_protocol_name, sizeof(noise_protocol_name) - 1);
	memcpy(s->ck, s->h, 32);
	crypto_hash_sha256(s->h, s->ck, 32);
	memset(&s->c, 0, sizeof(s->c));
}

static void mix_hash(unsigned char h[32], const unsigned char *data, size_t len) {
	crypto_hash_sha256_state st;
	crypto_hash_sha256_init(&st);
	crypto_hash_sha256_update(&st, h, 32);
	crypto_hash_sha256_update(&st, data, len);
	crypto_hash_sha256_final(&st, h);
}

static void hmac_sha256(unsigned char out[32], const unsigned char key[32], const unsigned char *data, size_t len) {
	crypto_auth_hmacsha256_state st;
	crypto_auth_hmacsha256_init(&st, key, 32);
	crypto_auth_hmacsha256_update(&st, data, len);
	crypto_auth_hmacsha256_final(&st, out);
}

// HKDF (RFC 5869, empty info) producing two 32-byte outputs
static void hkdf2(const unsigned char ck[32], const unsigned char *ikm, size_t ikm_len, unsigned char out1[32], unsigned char out2[32]) {
	unsigned char temp_k[32], in2[33];
	unsigned char one = 0x01;

	hmac_sha256(temp_k, ck, ikm, ikm_len);
	hmac_sha256(out1, temp_k, &one, 1);
	memcpy(in2, out1, 32);
	in2[32] = 0x02;
	hmac_sha256(out2, temp_k, in2, 33);
	sodium_memzero(temp_k, sizeof(temp_k));
}

static void cipher_set_key(T_DATUM_SV2_CIPHER *c, const unsigned char k[32]) {
	memcpy(c->k, k, 32);
	c->n = 0;
	c->has_key = true;
}

static void mix_key(T_NOISE_SYM *s, const unsigned char *ikm, size_t ikm_len) {
	unsigned char ck[32], temp_k[32];
	hkdf2(s->ck, ikm, ikm_len, ck, temp_k);
	memcpy(s->ck, ck, 32);
	cipher_set_key(&s->c, temp_k);
	sodium_memzero(temp_k, sizeof(temp_k));
}

static void cipher_nonce(const T_DATUM_SV2_CIPHER *c, unsigned char nonce[12]) {
	// 32 zero bits, then the 64-bit counter little-endian
	memset(nonce, 0, 4);
	pk_u64le(nonce, 4, c->n);
}

// out may alias pt; out receives pt_len + MAC bytes
static bool cipher_encrypt(T_DATUM_SV2_CIPHER *c, const unsigned char *ad, size_t ad_len, const unsigned char *pt, size_t pt_len, unsigned char *out) {
	unsigned char nonce[12];
	unsigned long long ct_len;

	if (c->n == UINT64_MAX) return false; // nonce 2^64-1 is reserved
	cipher_nonce(c, nonce);
	if (crypto_aead_chacha20poly1305_ietf_encrypt(out, &ct_len, pt, pt_len, ad, ad_len, NULL, nonce, c->k) != 0) return false;
	c->n++;
	return true;
}

// out may alias ct; ct_len includes the MAC. The counter only advances on success.
static bool cipher_decrypt(T_DATUM_SV2_CIPHER *c, const unsigned char *ad, size_t ad_len, const unsigned char *ct, size_t ct_len, unsigned char *out) {
	unsigned char nonce[12];
	unsigned long long pt_len;

	if (c->n == UINT64_MAX) return false;
	if (ct_len < DATUM_SV2_NOISE_MAC_LEN) return false;
	cipher_nonce(c, nonce);
	if (crypto_aead_chacha20poly1305_ietf_decrypt(out, &pt_len, NULL, ct, ct_len, ad, ad_len, nonce, c->k) != 0) return false;
	c->n++;
	return true;
}

// Both handshake payloads that get encrypted are sent after a MixKey, so the
// no-key passthrough case only covers the empty payload of act 1.
static bool encrypt_and_hash(T_NOISE_SYM *s, const unsigned char *pt, size_t pt_len, unsigned char *out) {
	size_t out_len = pt_len;
	if (s->c.has_key) {
		if (!cipher_encrypt(&s->c, s->h, 32, pt, pt_len, out)) return false;
		out_len += DATUM_SV2_NOISE_MAC_LEN;
	} else if (pt_len) {
		memmove(out, pt, pt_len);
	}
	mix_hash(s->h, out, out_len);
	return true;
}

static bool decrypt_and_hash(T_NOISE_SYM *s, const unsigned char *ct, size_t ct_len, unsigned char *out) {
	unsigned char h_next[32];

	// hash the ciphertext before out (which may alias ct) is overwritten
	memcpy(h_next, s->h, 32);
	mix_hash(h_next, ct, ct_len);
	if (s->c.has_key) {
		if (!cipher_decrypt(&s->c, s->h, 32, ct, ct_len, out)) return false;
	} else if (ct_len) {
		memmove(out, ct, ct_len);
	}
	memcpy(s->h, h_next, 32);
	return true;
}

static void split(const T_NOISE_SYM *s, T_DATUM_SV2_CIPHER *c1, T_DATUM_SV2_CIPHER *c2) {
	unsigned char k1[32], k2[32];
	hkdf2(s->ck, NULL, 0, k1, k2);
	cipher_set_key(c1, k1);
	cipher_set_key(c2, k2);
	sodium_memzero(k1, sizeof(k1));
	sodium_memzero(k2, sizeof(k2));
}

static void sym_wipe(T_NOISE_SYM *s) {
	sodium_memzero(s, sizeof(*s));
}

// BIP324-style x-only ECDH over ElligatorSwift encodings. Party A is the
// initiator; ell_a is always the initiator's key.
static bool ecdh(unsigned char out[32], const unsigned char ell_a[64], const unsigned char ell_b[64], const unsigned char sk[32], bool initiator) {
	return secp256k1_ellswift_xdh(secp_ctx, out, ell_a, ell_b, sk, initiator ? 0 : 1, secp256k1_ellswift_xdh_hash_function_bip324, NULL) == 1;
}

static bool xonly_from_sk(unsigned char out[32], const unsigned char sk[32]) {
	secp256k1_keypair kp;
	secp256k1_xonly_pubkey xpk;
	bool ok = secp256k1_keypair_create(secp_ctx, &kp, sk) &&
	          secp256k1_keypair_xonly_pub(secp_ctx, &xpk, NULL, &kp) &&
	          secp256k1_xonly_pubkey_serialize(secp_ctx, out, &xpk);
	sodium_memzero(&kp, sizeof(kp));
	return ok;
}

// The signed message is SHA256(version || valid_from || not_valid_after || static_pk_xonly)
static void cert_digest(unsigned char out[32], const unsigned char cert_head[10], const unsigned char static_pk_xonly[32]) {
	crypto_hash_sha256_state st;
	crypto_hash_sha256_init(&st);
	crypto_hash_sha256_update(&st, cert_head, 10);
	crypto_hash_sha256_update(&st, static_pk_xonly, 32);
	crypto_hash_sha256_final(&st, out);
}

static bool cert_sign(const T_DATUM_SV2_NOISE_IDENTITY *id, uint32_t now, const unsigned char aux[32], unsigned char cert[DATUM_SV2_NOISE_CERT_LEN]) {
	secp256k1_keypair kp;
	unsigned char digest[32];
	uint32_t not_valid_after = (now > UINT32_MAX - id->cert_validity) ? UINT32_MAX : now + id->cert_validity;
	bool ok;

	pk_u16le(cert, 0, DATUM_SV2_NOISE_CERT_VERSION);
	pk_u32le(cert, 2, now);
	pk_u32le(cert, 6, not_valid_after);
	cert_digest(digest, cert, id->static_pk_xonly);
	ok = secp256k1_keypair_create(secp_ctx, &kp, id->authority_sk) &&
	     secp256k1_schnorrsig_sign32(secp_ctx, &cert[10], digest, &kp, aux);
	sodium_memzero(&kp, sizeof(kp));
	return ok;
}

static bool cert_verify(const unsigned char cert[DATUM_SV2_NOISE_CERT_LEN], const unsigned char static_pk_xonly[32], const unsigned char authority_pk_xonly[32], uint32_t now) {
	secp256k1_xonly_pubkey apk;
	unsigned char digest[32];
	uint32_t valid_from = upk_u32le(cert, 2), not_valid_after = upk_u32le(cert, 6);

	if (upk_u16le(cert, 0) != DATUM_SV2_NOISE_CERT_VERSION) return false;
	// valid_from - leeway <= now <= not_valid_after + leeway, saturating
	if (valid_from > DATUM_SV2_NOISE_CERT_LEEWAY && valid_from - DATUM_SV2_NOISE_CERT_LEEWAY > now) return false;
	if (not_valid_after < UINT32_MAX - DATUM_SV2_NOISE_CERT_LEEWAY && not_valid_after + DATUM_SV2_NOISE_CERT_LEEWAY < now) return false;
	if (!secp256k1_xonly_pubkey_parse(secp_ctx, &apk, authority_pk_xonly)) return false;
	cert_digest(digest, cert, static_pk_xonly);
	return secp256k1_schnorrsig_verify(secp_ctx, &cert[10], digest, 32, &apk) == 1;
}

static void fill_rand(T_DATUM_SV2_NOISE_RAND *rnd) {
	do {
		randombytes_buf(rnd->e_sk, 32);
	} while (!secp256k1_ec_seckey_verify(secp_ctx, rnd->e_sk));
	randombytes_buf(rnd->e_ell_aux, 32);
	randombytes_buf(rnd->s_ell_aux, 32);
	randombytes_buf(rnd->sig_aux, 32);
}

// --- identity ---

bool datum_sv2_noise_identity_init_with_static(T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char authority_sk[32], const unsigned char static_sk[32], uint32_t cert_validity) {
	if (!datum_sv2_noise_init()) return false;
	memset(id, 0, sizeof(*id));
	memcpy(id->authority_sk, authority_sk, 32);
	memcpy(id->static_sk, static_sk, 32);
	id->cert_validity = cert_validity;
	if (!xonly_from_sk(id->authority_pk_xonly, id->authority_sk) || !xonly_from_sk(id->static_pk_xonly, id->static_sk)) {
		sodium_memzero(id, sizeof(*id));
		return false;
	}
	return true;
}

bool datum_sv2_noise_identity_init(T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char authority_sk[32], uint32_t cert_validity) {
	unsigned char static_sk[32];
	bool ok;

	if (!datum_sv2_noise_init()) return false;
	do {
		randombytes_buf(static_sk, 32);
	} while (!secp256k1_ec_seckey_verify(secp_ctx, static_sk));
	ok = datum_sv2_noise_identity_init_with_static(id, authority_sk, static_sk, cert_validity);
	sodium_memzero(static_sk, sizeof(static_sk));
	return ok;
}

// --- responder ---

bool datum_sv2_noise_respond_with_rand(const T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], unsigned char act2[DATUM_SV2_NOISE_ACT2_LEN], T_DATUM_SV2_NOISE_SESSION *session, uint32_t now, const T_DATUM_SV2_NOISE_RAND *rnd) {
	T_NOISE_SYM s;
	unsigned char shared[32], cert[DATUM_SV2_NOISE_CERT_LEN];
	unsigned char *e_ell = &act2[0];
	unsigned char *enc_s = &act2[DATUM_SV2_NOISE_ELLSWIFT_LEN];
	unsigned char *enc_cert = &act2[DATUM_SV2_NOISE_ELLSWIFT_LEN * 2 + DATUM_SV2_NOISE_MAC_LEN];
	bool ok = false;

	if (!datum_sv2_noise_init()) return false;
	sym_init(&s);

	// -> e
	mix_hash(s.h, act1, DATUM_SV2_NOISE_ACT1_LEN);
	if (!decrypt_and_hash(&s, NULL, 0, NULL)) goto out;

	// <- e
	if (!secp256k1_ellswift_create(secp_ctx, e_ell, rnd->e_sk, rnd->e_ell_aux)) goto out;
	mix_hash(s.h, e_ell, DATUM_SV2_NOISE_ELLSWIFT_LEN);

	// ee
	if (!ecdh(shared, act1, e_ell, rnd->e_sk, false)) goto out;
	mix_key(&s, shared, 32);

	// s
	if (!secp256k1_ellswift_create(secp_ctx, enc_s, id->static_sk, rnd->s_ell_aux)) goto out;
	// ecdh below needs the plaintext encoding, so take it before encrypting in place
	{
		unsigned char s_ell[DATUM_SV2_NOISE_ELLSWIFT_LEN];
		memcpy(s_ell, enc_s, sizeof(s_ell));
		if (!encrypt_and_hash(&s, enc_s, DATUM_SV2_NOISE_ELLSWIFT_LEN, enc_s)) goto out;

		// es
		if (!ecdh(shared, act1, s_ell, id->static_sk, false)) goto out;
		mix_key(&s, shared, 32);
	}

	// signature noise message
	if (!cert_sign(id, now, rnd->sig_aux, cert)) goto out;
	if (!encrypt_and_hash(&s, cert, DATUM_SV2_NOISE_CERT_LEN, enc_cert)) goto out;

	// c1 carries initiator -> responder traffic
	split(&s, &session->decrypt, &session->encrypt);
	ok = true;

out:
	sym_wipe(&s);
	sodium_memzero(shared, sizeof(shared));
	if (!ok) sodium_memzero(session, sizeof(*session));
	return ok;
}

bool datum_sv2_noise_respond(const T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], unsigned char act2[DATUM_SV2_NOISE_ACT2_LEN], T_DATUM_SV2_NOISE_SESSION *session, uint32_t now) {
	T_DATUM_SV2_NOISE_RAND rnd;
	bool ok;

	if (!datum_sv2_noise_init()) return false;
	fill_rand(&rnd);
	ok = datum_sv2_noise_respond_with_rand(id, act1, act2, session, now, &rnd);
	sodium_memzero(&rnd, sizeof(rnd));
	return ok;
}

// --- initiator ---
// The gateway only ever responds. The initiator is the miner's side, kept here so the
// tests can drive the responder through real handshakes.

bool datum_sv2_noise_initiate_with_rand(T_DATUM_SV2_NOISE_INITIATOR *st, unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], const T_DATUM_SV2_NOISE_RAND *rnd) {
	T_NOISE_SYM s;

	if (!datum_sv2_noise_init()) return false;
	sym_init(&s);
	memcpy(st->e_sk, rnd->e_sk, 32);
	if (!secp256k1_ellswift_create(secp_ctx, st->e_ell, st->e_sk, rnd->e_ell_aux)) {
		sym_wipe(&s);
		sodium_memzero(st, sizeof(*st));
		return false;
	}
	mix_hash(s.h, st->e_ell, DATUM_SV2_NOISE_ELLSWIFT_LEN);
	encrypt_and_hash(&s, NULL, 0, NULL);
	memcpy(act1, st->e_ell, DATUM_SV2_NOISE_ACT1_LEN);
	memcpy(st->h, s.h, 32);
	memcpy(st->ck, s.ck, 32);
	sym_wipe(&s);
	return true;
}

bool datum_sv2_noise_initiate(T_DATUM_SV2_NOISE_INITIATOR *st, unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN]) {
	T_DATUM_SV2_NOISE_RAND rnd;
	bool ok;

	if (!datum_sv2_noise_init()) return false;
	fill_rand(&rnd);
	ok = datum_sv2_noise_initiate_with_rand(st, act1, &rnd);
	sodium_memzero(&rnd, sizeof(rnd));
	return ok;
}

bool datum_sv2_noise_initiator_finish(T_DATUM_SV2_NOISE_INITIATOR *st, const unsigned char act2[DATUM_SV2_NOISE_ACT2_LEN], const unsigned char *authority_pk_xonly, uint32_t now, T_DATUM_SV2_NOISE_SESSION *session) {
	T_NOISE_SYM s;
	unsigned char shared[32], rs_ell[DATUM_SV2_NOISE_ELLSWIFT_LEN], cert[DATUM_SV2_NOISE_CERT_LEN], rs_xonly[32];
	const unsigned char *re_ell = &act2[0];
	const unsigned char *enc_s = &act2[DATUM_SV2_NOISE_ELLSWIFT_LEN];
	const unsigned char *enc_cert = &act2[DATUM_SV2_NOISE_ELLSWIFT_LEN * 2 + DATUM_SV2_NOISE_MAC_LEN];
	secp256k1_pubkey rs_pk;
	secp256k1_xonly_pubkey rs_xpk;
	bool ok = false;

	if (!datum_sv2_noise_init()) return false;
	memset(&s, 0, sizeof(s));
	memcpy(s.h, st->h, 32);
	memcpy(s.ck, st->ck, 32);

	// <- e, ee
	mix_hash(s.h, re_ell, DATUM_SV2_NOISE_ELLSWIFT_LEN);
	if (!ecdh(shared, st->e_ell, re_ell, st->e_sk, true)) goto out;
	mix_key(&s, shared, 32);

	// s, es
	if (!decrypt_and_hash(&s, enc_s, DATUM_SV2_NOISE_ELLSWIFT_LEN + DATUM_SV2_NOISE_MAC_LEN, rs_ell)) goto out;
	if (!ecdh(shared, st->e_ell, rs_ell, st->e_sk, true)) goto out;
	mix_key(&s, shared, 32);

	// signature noise message
	if (!decrypt_and_hash(&s, enc_cert, DATUM_SV2_NOISE_CERT_LEN + DATUM_SV2_NOISE_MAC_LEN, cert)) goto out;
	if (authority_pk_xonly) {
		if (!secp256k1_ellswift_decode(secp_ctx, &rs_pk, rs_ell)) goto out;
		if (!secp256k1_xonly_pubkey_from_pubkey(secp_ctx, &rs_xpk, NULL, &rs_pk)) goto out;
		if (!secp256k1_xonly_pubkey_serialize(secp_ctx, rs_xonly, &rs_xpk)) goto out;
		if (!cert_verify(cert, rs_xonly, authority_pk_xonly, now)) goto out;
	}

	split(&s, &session->encrypt, &session->decrypt);
	ok = true;

out:
	sym_wipe(&s);
	sodium_memzero(shared, sizeof(shared));
	sodium_memzero(st, sizeof(*st));
	if (!ok) sodium_memzero(session, sizeof(*session));
	return ok;
}

// --- transport ---

size_t datum_sv2_noise_payload_ct_len(size_t pt_len) {
	size_t full = pt_len / DATUM_SV2_NOISE_MAX_PT_CHUNK;
	size_t rem = pt_len % DATUM_SV2_NOISE_MAX_PT_CHUNK;
	return full * DATUM_SV2_NOISE_MAX_CT_CHUNK + (rem ? rem + DATUM_SV2_NOISE_MAC_LEN : 0);
}

bool datum_sv2_noise_encrypt_frame(T_DATUM_SV2_CIPHER *c, const unsigned char header[DATUM_SV2_FRAME_HEADER_LEN], const unsigned char *payload, size_t payload_len, unsigned char *out, size_t *out_len) {
	size_t i = 0, o;

	if (!c->has_key) return false;
	if (!cipher_encrypt(c, NULL, 0, header, DATUM_SV2_FRAME_HEADER_LEN, out)) return false;
	o = DATUM_SV2_NOISE_HEADER_CT_LEN;
	while (i < payload_len) {
		size_t chunk = payload_len - i;
		if (chunk > DATUM_SV2_NOISE_MAX_PT_CHUNK) chunk = DATUM_SV2_NOISE_MAX_PT_CHUNK;
		if (!cipher_encrypt(c, NULL, 0, &payload[i], chunk, &out[o])) return false;
		i += chunk;
		o += chunk + DATUM_SV2_NOISE_MAC_LEN;
	}
	*out_len = o;
	return true;
}

bool datum_sv2_noise_decrypt_header(T_DATUM_SV2_CIPHER *c, const unsigned char in[DATUM_SV2_NOISE_HEADER_CT_LEN], unsigned char header[DATUM_SV2_FRAME_HEADER_LEN]) {
	if (!c->has_key) return false;
	return cipher_decrypt(c, NULL, 0, in, DATUM_SV2_NOISE_HEADER_CT_LEN, header);
}

bool datum_sv2_noise_decrypt_payload(T_DATUM_SV2_CIPHER *c, const unsigned char *in, size_t payload_len, unsigned char *out) {
	size_t i = 0, o = 0;

	if (!c->has_key) return false;
	while (o < payload_len) {
		size_t chunk = payload_len - o;
		if (chunk > DATUM_SV2_NOISE_MAX_PT_CHUNK) chunk = DATUM_SV2_NOISE_MAX_PT_CHUNK;
		if (!cipher_decrypt(c, NULL, 0, &in[i], chunk + DATUM_SV2_NOISE_MAC_LEN, &out[o])) return false;
		i += chunk + DATUM_SV2_NOISE_MAC_LEN;
		o += chunk;
	}
	return true;
}

void datum_sv2_noise_session_wipe(T_DATUM_SV2_NOISE_SESSION *session) {
	sodium_memzero(session, sizeof(*session));
}
