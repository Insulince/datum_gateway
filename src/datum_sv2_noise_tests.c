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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "datum_sv2_noise.h"
#include "datum_utils.h"

static void fill(unsigned char *p, size_t len, unsigned char seed) {
	for (size_t i = 0; i < len; i++) p[i] = (unsigned char)(seed + i * 7);
}

static void make_rand(T_DATUM_SV2_NOISE_RAND *r, unsigned char seed) {
	fill(r->e_sk, 32, seed);
	fill(r->e_ell_aux, 32, seed + 1);
	fill(r->s_ell_aux, 32, seed + 2);
	fill(r->sig_aux, 32, seed + 3);
}

// Pinned against NOISE_HASHED_PROTOCOL_NAME_CHACHA in the SRI noise_sv2 crate.
static void datum_sv2_noise_tests_protocol_name(void) {
	static const unsigned char expected[32] = {
		46, 180, 120, 129, 32, 142, 158, 238, 31, 102, 159, 103, 198, 110, 231, 14,
		169, 234, 136, 9, 13, 80, 63, 232, 48, 220, 75, 200, 62, 41, 191, 16,
	};
	static const char name[] = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256";
	unsigned char h[32];
	crypto_hash_sha256(h, (const unsigned char *)name, sizeof(name) - 1);
	datum_test(0 == memcmp(h, expected, 32));
}

static bool handshake(const T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char *pin, uint32_t now_r, uint32_t now_i, T_DATUM_SV2_NOISE_SESSION *ini, T_DATUM_SV2_NOISE_SESSION *resp) {
	T_DATUM_SV2_NOISE_INITIATOR st;
	unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], act2[DATUM_SV2_NOISE_ACT2_LEN];

	if (!datum_sv2_noise_initiate(&st, act1)) return false;
	if (!datum_sv2_noise_respond(id, act1, act2, resp, now_r)) return false;
	return datum_sv2_noise_initiator_finish(&st, act2, pin, now_i, ini);
}

static bool send_frame(T_DATUM_SV2_CIPHER *enc, T_DATUM_SV2_CIPHER *dec, const unsigned char *payload, size_t len) {
	unsigned char header[DATUM_SV2_FRAME_HEADER_LEN] = { 0x00, 0x00, 0x15, (unsigned char)len, (unsigned char)(len >> 8), (unsigned char)(len >> 16) };
	unsigned char got_header[DATUM_SV2_FRAME_HEADER_LEN];
	size_t ct_len = DATUM_SV2_NOISE_HEADER_CT_LEN + datum_sv2_noise_payload_ct_len(len), out_len = 0;
	unsigned char *ct = malloc(ct_len), *pt = malloc(len ? len : 1);
	bool ok = false;

	if (!ct || !pt) goto out;
	if (!datum_sv2_noise_encrypt_frame(enc, header, payload, len, ct, &out_len)) goto out;
	if (out_len != ct_len) goto out;
	if (!datum_sv2_noise_decrypt_header(dec, ct, got_header)) goto out;
	if (memcmp(header, got_header, sizeof(header))) goto out;
	if (!datum_sv2_noise_decrypt_payload(dec, &ct[DATUM_SV2_NOISE_HEADER_CT_LEN], len, pt)) goto out;
	ok = (0 == memcmp(payload, pt, len));
out:
	free(ct);
	free(pt);
	return ok;
}

static void datum_sv2_noise_tests_roundtrip(void) {
	T_DATUM_SV2_NOISE_IDENTITY id;
	T_DATUM_SV2_NOISE_SESSION ini, resp;
	unsigned char authority_sk[32], wrong_pin[32];
	unsigned char small[100];
	const size_t big_len = DATUM_SV2_NOISE_MAX_PT_CHUNK * 2 + 123; // three chunks
	unsigned char *big = malloc(big_len);
	const uint32_t now = 1760000000;

	fill(authority_sk, 32, 0x11);
	fill(small, sizeof(small), 0x42);
	datum_test(big != NULL);
	if (!big) return;
	fill(big, big_len, 0x99);

	datum_test(datum_sv2_noise_identity_init(&id, authority_sk, 3600));
	datum_test(handshake(&id, id.authority_pk_xonly, now, now, &ini, &resp));

	// both directions, several frames, so nonces advance in step
	datum_test(send_frame(&ini.encrypt, &resp.decrypt, small, sizeof(small)));
	datum_test(send_frame(&resp.encrypt, &ini.decrypt, small, sizeof(small)));
	datum_test(send_frame(&ini.encrypt, &resp.decrypt, big, big_len));
	datum_test(send_frame(&resp.encrypt, &ini.decrypt, big, big_len));
	datum_test(send_frame(&ini.encrypt, &resp.decrypt, small, 0));
	datum_test(ini.encrypt.n == resp.decrypt.n);
	datum_test(resp.encrypt.n == ini.decrypt.n);

	// wrong authority pin
	memcpy(wrong_pin, id.authority_pk_xonly, 32);
	wrong_pin[31] ^= 1;
	datum_test(!handshake(&id, wrong_pin, now, now, &ini, &resp));

	// certificate window, with the 10 s leeway on both ends
	datum_test(handshake(&id, id.authority_pk_xonly, now, now - DATUM_SV2_NOISE_CERT_LEEWAY, &ini, &resp));
	datum_test(!handshake(&id, id.authority_pk_xonly, now, now - DATUM_SV2_NOISE_CERT_LEEWAY - 1, &ini, &resp));
	datum_test(handshake(&id, id.authority_pk_xonly, now, now + 3600 + DATUM_SV2_NOISE_CERT_LEEWAY, &ini, &resp));
	datum_test(!handshake(&id, id.authority_pk_xonly, now, now + 3600 + DATUM_SV2_NOISE_CERT_LEEWAY + 1, &ini, &resp));

	// unauthenticated mode still agrees on keys
	datum_test(handshake(&id, NULL, now, 0, &ini, &resp));
	datum_test(send_frame(&ini.encrypt, &resp.decrypt, small, sizeof(small)));

	free(big);
}

static void datum_sv2_noise_tests_tamper(void) {
	T_DATUM_SV2_NOISE_IDENTITY id;
	T_DATUM_SV2_NOISE_INITIATOR st;
	T_DATUM_SV2_NOISE_SESSION ini, resp;
	T_DATUM_SV2_NOISE_RAND ri, rr;
	unsigned char authority_sk[32], static_sk[32];
	unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], act2[DATUM_SV2_NOISE_ACT2_LEN], act2b[DATUM_SV2_NOISE_ACT2_LEN];
	unsigned char header[DATUM_SV2_FRAME_HEADER_LEN] = { 0, 0, 0x15, 4, 0, 0 };
	unsigned char payload[4] = { 1, 2, 3, 4 }, ct[DATUM_SV2_NOISE_HEADER_CT_LEN + 4 + DATUM_SV2_NOISE_MAC_LEN], got[DATUM_SV2_FRAME_HEADER_LEN];
	size_t ct_len;
	uint64_t n;
	const uint32_t now = 1760000000;

	fill(authority_sk, 32, 0x21);
	fill(static_sk, 32, 0x31);
	make_rand(&ri, 0x41);
	make_rand(&rr, 0x51);
	datum_test(datum_sv2_noise_identity_init_with_static(&id, authority_sk, static_sk, 3600));

	// deterministic with injected randomness
	datum_test(datum_sv2_noise_initiate_with_rand(&st, act1, &ri));
	datum_test(datum_sv2_noise_respond_with_rand(&id, act1, act2, &resp, now, &rr));
	datum_test(datum_sv2_noise_respond_with_rand(&id, act1, act2b, &ini, now, &rr));
	datum_test(0 == memcmp(act2, act2b, sizeof(act2)));

	// any flipped bit in act 2 fails the handshake
	for (size_t i = 0; i < DATUM_SV2_NOISE_ACT2_LEN; i += 13) {
		memcpy(act2b, act2, sizeof(act2));
		act2b[i] ^= 0x01;
		datum_test(datum_sv2_noise_initiate_with_rand(&st, act1, &ri));
		datum_test(!datum_sv2_noise_initiator_finish(&st, act2b, id.authority_pk_xonly, now, &ini));
	}

	datum_test(datum_sv2_noise_initiate_with_rand(&st, act1, &ri));
	datum_test(datum_sv2_noise_initiator_finish(&st, act2, id.authority_pk_xonly, now, &ini));

	// a flipped bit in a transport frame fails, and does not advance the nonce
	datum_test(datum_sv2_noise_encrypt_frame(&ini.encrypt, header, payload, sizeof(payload), ct, &ct_len));
	ct[3] ^= 0x80;
	n = resp.decrypt.n;
	datum_test(!datum_sv2_noise_decrypt_header(&resp.decrypt, ct, got));
	datum_test(resp.decrypt.n == n);
	ct[3] ^= 0x80;
	datum_test(datum_sv2_noise_decrypt_header(&resp.decrypt, ct, got));
	ct[DATUM_SV2_NOISE_HEADER_CT_LEN] ^= 0x01;
	datum_test(!datum_sv2_noise_decrypt_payload(&resp.decrypt, &ct[DATUM_SV2_NOISE_HEADER_CT_LEN], sizeof(payload), got));

	// replaying the act 2 of another session fails
	datum_test(datum_sv2_noise_initiate(&st, act1));
	datum_test(!datum_sv2_noise_initiator_finish(&st, act2, id.authority_pk_xonly, now, &ini));
}

static void unhex(const char *s, unsigned char *out, size_t n) {
	for (size_t i = 0; i < n; i++) out[i] = hex2bin_uchar(&s[2 * i]);
}

// Transcripts produced against the SRI noise_sv2 2.0.0 crate, at now = 1760000000.
// The frame in each carries header 00 00 15 25 00 00 and payload bytes 0x00..0x24.
static const unsigned char sri_frame_header[DATUM_SV2_FRAME_HEADER_LEN] = { 0x00, 0x00, 0x15, 0x25, 0x00, 0x00 };

static bool sri_frame_check(T_DATUM_SV2_CIPHER *dec, const char *header_hex, const char *payload_hex) {
	unsigned char hct[DATUM_SV2_NOISE_HEADER_CT_LEN], pct[37 + DATUM_SV2_NOISE_MAC_LEN], header[DATUM_SV2_FRAME_HEADER_LEN], payload[37];
	unhex(header_hex, hct, sizeof(hct));
	unhex(payload_hex, pct, sizeof(pct));
	if (!datum_sv2_noise_decrypt_header(dec, hct, header)) return false;
	if (memcmp(header, sri_frame_header, sizeof(header))) return false;
	if (!datum_sv2_noise_decrypt_payload(dec, pct, sizeof(payload), payload)) return false;
	for (size_t i = 0; i < sizeof(payload); i++) if (payload[i] != i) return false;
	return true;
}

// Our initiator against the SRI responder
static void datum_sv2_noise_tests_sri_responder(void) {
	static const char act1_hex[] = "622dbe82c6d16452a72d5cc922de1516230e5003667df52310686911efe82ee9feae30e530adb8c8dfe72932439deb128da8ab5b5edc9aef2875cb0c90235a8b";
	static const char authority_hex[] = "9c5530e4385ebc41cdaf8257edf9a2baaf8506a4099103211e6ed7382103ed67";
	static const char act2_hex[] =
		"684fdff12458c4f04d01ba62ac880fb9d06807a27a2d499f87d6a46af9364f50ce15b892b97bc7b344cc031bf71c77e3b5ef094c4c03323a07fb881fcdaeada0"
		"4d618d4aafe30b9dc7388a874e6817d4e8e1c50840d0522cb9db1af3d2903b60fc83b64c6501a870d6fe4972fefcb95d114df0e0168d6028f3da75218fcc0494"
		"c3a97691fedc0e4a7bf073247b6d261054d8fabfe4d70eb151e693a2218359a9d5207791e9517460bced29a0499c8eeafed01209cd454b3377b9ad597dd83d96"
		"b60c5042908dbead092a9da975ba9f3b1001a9107539306b71e04aa5351a200ed8cdcbb926d6ebe2b1d7";
	T_DATUM_SV2_NOISE_RAND r;
	T_DATUM_SV2_NOISE_INITIATOR st;
	T_DATUM_SV2_NOISE_SESSION s;
	unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], want_act1[DATUM_SV2_NOISE_ACT1_LEN], act2[DATUM_SV2_NOISE_ACT2_LEN], authority[32];

	make_rand(&r, 0x41);
	unhex(act1_hex, want_act1, sizeof(want_act1));
	unhex(act2_hex, act2, sizeof(act2));
	unhex(authority_hex, authority, sizeof(authority));
	datum_test(datum_sv2_noise_initiate_with_rand(&st, act1, &r));
	datum_test(0 == memcmp(act1, want_act1, sizeof(act1)));
	datum_test(datum_sv2_noise_initiator_finish(&st, act2, authority, 1760000000, &s));
	datum_test(sri_frame_check(&s.decrypt,
		"c6829e83274b043b8fc730e512e0fe443a4a52bb8210",
		"55c42c5181da2e16cf57a80065efde9dca546e1a2381850468463af4be8b6e156efa0ac47cde2db620167b3cc21cc6d9ad9172cbdd"));
}

// The SRI initiator against our responder; SRI accepted this act 2 and its certificate
static void datum_sv2_noise_tests_sri_initiator(void) {
	static const char act1_hex[] = "e9cc6415cd322fcb12057affc78cb91d7252235c51da29a3132671125e7bd4f9cbbefbfe2723eccbc90690915bafddf496421493698123239d35db215dc67e7e";
	static const char authority_hex[] = "7fd738cb67baa2c6818850e56b2c7fe7de87130964dc1c2210b143a8e97bd0a6";
	static const char act2_hex[] =
		"07eff393374c986cebc6825c3490d66bfc59dc784b51bdb1656b400da05dad54a17e37a9c8cf987eb1523e5d5c9e05c740a299f1e4b7e23123ec5eedf78c5fbf"
		"e1b3af3659aeaeacb2b9ed35bac010a437a44da94a89f76869e70d58baf464ec1ec75e86d7190cc46ac4bae79815ef35f6556e775ca7d3f5c7bdb7ebf3c3581d"
		"d8b56fadf56493d7540059db85cc6243a6399974993cc8f6271315116db40070c202c062a0a9fb435f890abe538ca895d768d873b403b24886c1d49fb3d01b9f"
		"818a65f0a90a33a70a4574f2545497719012e532da13275f8cebc660abf064d3eb8e92e0025709ef9cca";
	T_DATUM_SV2_NOISE_IDENTITY id;
	T_DATUM_SV2_NOISE_RAND r;
	T_DATUM_SV2_NOISE_SESSION s;
	unsigned char authority_sk[32], static_sk[32], authority[32];
	unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], act2[DATUM_SV2_NOISE_ACT2_LEN], want_act2[DATUM_SV2_NOISE_ACT2_LEN];

	fill(authority_sk, 32, 0x21);
	fill(static_sk, 32, 0x31);
	make_rand(&r, 0x51);
	unhex(act1_hex, act1, sizeof(act1));
	unhex(act2_hex, want_act2, sizeof(want_act2));
	unhex(authority_hex, authority, sizeof(authority));
	datum_test(datum_sv2_noise_identity_init_with_static(&id, authority_sk, static_sk, 3600));
	datum_test(0 == memcmp(id.authority_pk_xonly, authority, sizeof(authority)));
	datum_test(datum_sv2_noise_respond_with_rand(&id, act1, act2, &s, 1760000000, &r));
	datum_test(0 == memcmp(act2, want_act2, sizeof(act2)));
	datum_test(sri_frame_check(&s.decrypt,
		"9fba951a32a81542794676532a36b844bafc6164759c",
		"c0e5bbb861dc62ccf336d08c1839ce94f84e168d5557c5b19e3add06ade20f8ad24338125091ef005a7be5941dad289e8a8f1d3862"));
}

static void datum_sv2_noise_tests_ct_len(void) {
	datum_test(datum_sv2_noise_payload_ct_len(0) == 0);
	datum_test(datum_sv2_noise_payload_ct_len(1) == 17);
	datum_test(datum_sv2_noise_payload_ct_len(DATUM_SV2_NOISE_MAX_PT_CHUNK) == DATUM_SV2_NOISE_MAX_CT_CHUNK);
	datum_test(datum_sv2_noise_payload_ct_len(DATUM_SV2_NOISE_MAX_PT_CHUNK + 1) == DATUM_SV2_NOISE_MAX_CT_CHUNK + 17);
}

void datum_sv2_noise_tests(void) {
	datum_test(datum_sv2_noise_init());
	datum_sv2_noise_tests_protocol_name();
	datum_sv2_noise_tests_ct_len();
	datum_sv2_noise_tests_roundtrip();
	datum_sv2_noise_tests_tamper();
	datum_sv2_noise_tests_sri_responder();
	datum_sv2_noise_tests_sri_initiator();
}
