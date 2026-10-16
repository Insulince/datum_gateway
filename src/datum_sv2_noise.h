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

// Stratum V2 Noise transport (sv2-spec 04-Protocol-Security):
//   Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256
//
//   -> e                                  act 1:  64 bytes
//   <- e, ee, s, es, SIGNATURE_NOISE_MSG  act 2: 234 bytes
//
// The gateway is always the responder. The initiator half exists so the
// handshake can be exercised end to end in --test.

#ifndef _DATUM_SV2_NOISE_H_
#define _DATUM_SV2_NOISE_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DATUM_SV2_NOISE_KEY_LEN 32
#define DATUM_SV2_NOISE_ELLSWIFT_LEN 64
#define DATUM_SV2_NOISE_MAC_LEN 16
#define DATUM_SV2_NOISE_CERT_LEN 74 // version u16, valid_from u32, not_valid_after u32, schnorr sig 64
#define DATUM_SV2_NOISE_ACT1_LEN DATUM_SV2_NOISE_ELLSWIFT_LEN
#define DATUM_SV2_NOISE_ACT2_LEN (DATUM_SV2_NOISE_ELLSWIFT_LEN + (DATUM_SV2_NOISE_ELLSWIFT_LEN + DATUM_SV2_NOISE_MAC_LEN) + (DATUM_SV2_NOISE_CERT_LEN + DATUM_SV2_NOISE_MAC_LEN))
#define DATUM_SV2_NOISE_CERT_VERSION 0
#define DATUM_SV2_NOISE_CERT_LEEWAY 10 // seconds, matches the reference implementation

// Transport framing: the 6-byte SV2 frame header is encrypted on its own,
// then the payload in chunks of at most MAX_CT_CHUNK ciphertext bytes.
#define DATUM_SV2_FRAME_HEADER_LEN 6
#define DATUM_SV2_NOISE_HEADER_CT_LEN (DATUM_SV2_FRAME_HEADER_LEN + DATUM_SV2_NOISE_MAC_LEN)
#define DATUM_SV2_NOISE_MAX_CT_CHUNK 65535
#define DATUM_SV2_NOISE_MAX_PT_CHUNK (DATUM_SV2_NOISE_MAX_CT_CHUNK - DATUM_SV2_NOISE_MAC_LEN)

typedef struct {
	unsigned char k[DATUM_SV2_NOISE_KEY_LEN];
	uint64_t n;
	bool has_key;
} T_DATUM_SV2_CIPHER;

// The two transport ciphers left after a completed handshake.
typedef struct {
	T_DATUM_SV2_CIPHER encrypt;
	T_DATUM_SV2_CIPHER decrypt;
} T_DATUM_SV2_NOISE_SESSION;

// Responder identity. The static key is signed by the authority key on every
// handshake (a certificate valid for cert_validity seconds from "now"), so
// miners pin only the authority public key.
typedef struct {
	unsigned char authority_sk[DATUM_SV2_NOISE_KEY_LEN];
	unsigned char authority_pk_xonly[DATUM_SV2_NOISE_KEY_LEN];
	unsigned char static_sk[DATUM_SV2_NOISE_KEY_LEN];
	unsigned char static_pk_xonly[DATUM_SV2_NOISE_KEY_LEN];
	uint32_t cert_validity;
} T_DATUM_SV2_NOISE_IDENTITY;

// Initiator state between sending act 1 and receiving act 2.
typedef struct {
	unsigned char h[32];
	unsigned char ck[32];
	unsigned char e_sk[DATUM_SV2_NOISE_KEY_LEN];
	unsigned char e_ell[DATUM_SV2_NOISE_ELLSWIFT_LEN];
} T_DATUM_SV2_NOISE_INITIATOR;

// Randomness consumed by one handshake step, injectable for tests.
typedef struct {
	unsigned char e_sk[32];        // ephemeral secret key
	unsigned char e_ell_aux[32];   // ElligatorSwift encoding randomness for e
	unsigned char s_ell_aux[32];   // ElligatorSwift encoding randomness for s (responder only)
	unsigned char sig_aux[32];     // BIP340 auxiliary randomness (responder only)
} T_DATUM_SV2_NOISE_RAND;

bool datum_sv2_noise_init(void);

// Fills an identity from an authority secret key, generating a fresh static key.
bool datum_sv2_noise_identity_init(T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char authority_sk[32], uint32_t cert_validity);
bool datum_sv2_noise_identity_init_with_static(T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char authority_sk[32], const unsigned char static_sk[32], uint32_t cert_validity);

// Responder: consume act 1, produce act 2 and the transport session.
bool datum_sv2_noise_respond(const T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], unsigned char act2[DATUM_SV2_NOISE_ACT2_LEN], T_DATUM_SV2_NOISE_SESSION *session, uint32_t now);
bool datum_sv2_noise_respond_with_rand(const T_DATUM_SV2_NOISE_IDENTITY *id, const unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], unsigned char act2[DATUM_SV2_NOISE_ACT2_LEN], T_DATUM_SV2_NOISE_SESSION *session, uint32_t now, const T_DATUM_SV2_NOISE_RAND *rnd);

// Initiator: produce act 1, then consume act 2. authority_pk_xonly may be NULL
// to skip certificate verification (unauthenticated, tests only).
bool datum_sv2_noise_initiate(T_DATUM_SV2_NOISE_INITIATOR *st, unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN]);
bool datum_sv2_noise_initiate_with_rand(T_DATUM_SV2_NOISE_INITIATOR *st, unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN], const T_DATUM_SV2_NOISE_RAND *rnd);
bool datum_sv2_noise_initiator_finish(T_DATUM_SV2_NOISE_INITIATOR *st, const unsigned char act2[DATUM_SV2_NOISE_ACT2_LEN], const unsigned char *authority_pk_xonly, uint32_t now, T_DATUM_SV2_NOISE_SESSION *session);

// Transport. Lengths are plaintext payload lengths unless named _ct_.
size_t datum_sv2_noise_payload_ct_len(size_t pt_len);
// out must hold DATUM_SV2_NOISE_HEADER_CT_LEN + datum_sv2_noise_payload_ct_len(payload_len) bytes.
bool datum_sv2_noise_encrypt_frame(T_DATUM_SV2_CIPHER *c, const unsigned char header[DATUM_SV2_FRAME_HEADER_LEN], const unsigned char *payload, size_t payload_len, unsigned char *out, size_t *out_len);
bool datum_sv2_noise_decrypt_header(T_DATUM_SV2_CIPHER *c, const unsigned char in[DATUM_SV2_NOISE_HEADER_CT_LEN], unsigned char header[DATUM_SV2_FRAME_HEADER_LEN]);
// in holds datum_sv2_noise_payload_ct_len(payload_len) bytes; out receives payload_len bytes.
bool datum_sv2_noise_decrypt_payload(T_DATUM_SV2_CIPHER *c, const unsigned char *in, size_t payload_len, unsigned char *out);

void datum_sv2_noise_session_wipe(T_DATUM_SV2_NOISE_SESSION *session);

#endif
