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

// Stratum V2 frame header and the Common + Mining protocol messages a
// work-providing server needs (sv2-spec 03 and 05). The messages that carry
// work (jobs, SetNewPrevHash, shares) have the BLAKE2b chain's layouts,
// described in doc/sv2_xbt.md. Encoders cover what the server sends, decoders
// what it receives; tests use the reverse directions.

#ifndef _DATUM_SV2_MSG_H_
#define _DATUM_SV2_MSG_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DATUM_SV2_CHANNEL_MSG_BIT 0x8000

// Common
#define DATUM_SV2_MSG_SETUP_CONNECTION 0x00
#define DATUM_SV2_MSG_SETUP_CONNECTION_SUCCESS 0x01
#define DATUM_SV2_MSG_SETUP_CONNECTION_ERROR 0x02
// Mining
#define DATUM_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL 0x10
#define DATUM_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS 0x11
#define DATUM_SV2_MSG_OPEN_MINING_CHANNEL_ERROR 0x12
#define DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL 0x13
#define DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS 0x14
#define DATUM_SV2_MSG_NEW_MINING_JOB 0x15
#define DATUM_SV2_MSG_UPDATE_CHANNEL 0x16
#define DATUM_SV2_MSG_UPDATE_CHANNEL_ERROR 0x17
#define DATUM_SV2_MSG_CLOSE_CHANNEL 0x18
#define DATUM_SV2_MSG_SUBMIT_SHARES_STANDARD 0x1a
#define DATUM_SV2_MSG_SUBMIT_SHARES_EXTENDED 0x1b
#define DATUM_SV2_MSG_SUBMIT_SHARES_SUCCESS 0x1c
#define DATUM_SV2_MSG_SUBMIT_SHARES_ERROR 0x1d
#define DATUM_SV2_MSG_NEW_EXTENDED_MINING_JOB 0x1f
#define DATUM_SV2_MSG_SET_NEW_PREV_HASH 0x20
#define DATUM_SV2_MSG_SET_TARGET 0x21

#define DATUM_SV2_PROTOCOL_MINING 0
#define DATUM_SV2_VERSION 2

// SetupConnection.flags (client) for the Mining Protocol
#define DATUM_SV2_FLAG_REQUIRES_STANDARD_JOBS (1u << 0)
#define DATUM_SV2_FLAG_REQUIRES_WORK_SELECTION (1u << 1)
#define DATUM_SV2_FLAG_REQUIRES_VERSION_ROLLING (1u << 2)
// SetupConnection.Success.flags (server)
#define DATUM_SV2_FLAG_REQUIRES_FIXED_VERSION (1u << 0)
#define DATUM_SV2_FLAG_REQUIRES_EXTENDED_CHANNELS (1u << 1)

#define DATUM_SV2_MAX_EXTRANONCE 32

typedef struct {
	uint16_t extension_type; // without the channel_msg bit
	bool channel_msg;
	uint8_t msg_type;
	uint32_t length; // U24
} T_DATUM_SV2_FRAME_HEADER;

// Strings and byte arrays are copied out, so decoded messages do not borrow the frame buffer.
typedef struct {
	uint8_t len;
	char s[256]; // NUL-terminated for convenience; len is authoritative
} T_DATUM_SV2_STR;

typedef struct {
	uint8_t len;
	unsigned char b[DATUM_SV2_MAX_EXTRANONCE];
} T_DATUM_SV2_B032;

typedef struct {
	uint8_t protocol;
	uint16_t min_version;
	uint16_t max_version;
	uint32_t flags;
	T_DATUM_SV2_STR endpoint_host;
	uint16_t endpoint_port;
	T_DATUM_SV2_STR vendor;
	T_DATUM_SV2_STR hardware_version;
	T_DATUM_SV2_STR firmware;
	T_DATUM_SV2_STR device_id;
} T_DATUM_SV2_SETUP_CONNECTION;

typedef struct {
	uint16_t used_version;
	uint32_t flags;
} T_DATUM_SV2_SETUP_CONNECTION_SUCCESS;

typedef struct {
	uint32_t flags;
	T_DATUM_SV2_STR error_code;
} T_DATUM_SV2_SETUP_CONNECTION_ERROR;

// OpenStandardMiningChannel, and OpenExtendedMiningChannel when extended is set
typedef struct {
	bool extended;
	uint32_t request_id;
	T_DATUM_SV2_STR user_identity;
	float nominal_hash_rate;
	unsigned char max_target[32]; // U256, little-endian
	uint16_t min_extranonce_size; // extended only
} T_DATUM_SV2_OPEN_CHANNEL;

// OpenStandardMiningChannel.Success, and OpenExtendedMiningChannel.Success when extended is set
typedef struct {
	bool extended;
	uint32_t request_id;
	uint32_t channel_id;
	unsigned char target[32];
	uint16_t extranonce_size; // extended only
	T_DATUM_SV2_B032 extranonce_prefix;
	uint32_t group_channel_id;
} T_DATUM_SV2_OPEN_CHANNEL_SUCCESS;

// OpenMiningChannel.Error
typedef struct {
	uint32_t request_id;
	T_DATUM_SV2_STR error_code;
} T_DATUM_SV2_OPEN_CHANNEL_ERROR;

typedef struct {
	uint32_t channel_id;
	float nominal_hash_rate;
	unsigned char max_target[32];
} T_DATUM_SV2_UPDATE_CHANNEL;

// UpdateChannel.Error, CloseChannel
typedef struct {
	uint32_t channel_id;
	T_DATUM_SV2_STR code;
} T_DATUM_SV2_CHANNEL_CODE;

// SubmitSharesStandard, and SubmitSharesExtended when extended is set
typedef struct {
	bool extended;
	uint32_t channel_id;
	uint32_t sequence_number;
	uint32_t job_id;
	uint64_t nonce; // the work's 8 nonce bytes, little-endian
	uint64_t ntime; // the work's 8 time bytes, little-endian
	T_DATUM_SV2_B032 extranonce; // extended only
} T_DATUM_SV2_SUBMIT_SHARES;

typedef struct {
	uint32_t channel_id;
	uint32_t last_sequence_number;
	uint32_t new_submits_accepted_count;
	uint64_t new_shares_sum;
} T_DATUM_SV2_SUBMIT_SHARES_SUCCESS;

typedef struct {
	uint32_t channel_id;
	uint32_t sequence_number;
	T_DATUM_SV2_STR error_code;
} T_DATUM_SV2_SUBMIT_SHARES_ERROR;

// NewMiningJob, and NewExtendedMiningJob when extended is set
typedef struct {
	bool extended;
	uint32_t channel_id;
	uint32_t job_id;
	bool has_ntime_start; // unset = future job, mined with SetNewPrevHash's ntime_start
	uint64_t ntime_start; // the work's 8 time bytes, little-endian
	unsigned char root[32]; // merkle_root (standard) or commitment (extended)
} T_DATUM_SV2_NEW_MINING_JOB;

typedef struct {
	uint32_t channel_id;
	uint32_t job_id;
	unsigned char prev_hash[32];
	uint64_t ntime_start;
	uint32_t nbits;
} T_DATUM_SV2_SET_NEW_PREV_HASH;

typedef struct {
	uint32_t channel_id;
	unsigned char maximum_target[32];
} T_DATUM_SV2_SET_TARGET;

// --- frame header ---
void datum_sv2_header_encode(unsigned char out[6], uint16_t extension_type, bool channel_msg, uint8_t msg_type, uint32_t length);
void datum_sv2_header_decode(const unsigned char in[6], T_DATUM_SV2_FRAME_HEADER *h);
// Whether the spec sets channel_msg for this core message type.
bool datum_sv2_msg_is_channel_msg(uint8_t msg_type);

// --- encoders: write the payload (no header) to out, return its length, or 0 if it does not fit ---
size_t datum_sv2_encode_setup_connection(const T_DATUM_SV2_SETUP_CONNECTION *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_setup_connection_success(const T_DATUM_SV2_SETUP_CONNECTION_SUCCESS *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_setup_connection_error(const T_DATUM_SV2_SETUP_CONNECTION_ERROR *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_open_channel(const T_DATUM_SV2_OPEN_CHANNEL *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_open_channel_success(const T_DATUM_SV2_OPEN_CHANNEL_SUCCESS *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_open_channel_error(const T_DATUM_SV2_OPEN_CHANNEL_ERROR *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_update_channel(const T_DATUM_SV2_UPDATE_CHANNEL *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_channel_code(const T_DATUM_SV2_CHANNEL_CODE *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_submit_shares(const T_DATUM_SV2_SUBMIT_SHARES *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_submit_shares_success(const T_DATUM_SV2_SUBMIT_SHARES_SUCCESS *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_submit_shares_error(const T_DATUM_SV2_SUBMIT_SHARES_ERROR *m, unsigned char *out, size_t cap);
// the message type follows m->extended, so callers pick it the same way
size_t datum_sv2_encode_new_mining_job(const T_DATUM_SV2_NEW_MINING_JOB *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_set_new_prev_hash(const T_DATUM_SV2_SET_NEW_PREV_HASH *m, unsigned char *out, size_t cap);
size_t datum_sv2_encode_set_target(const T_DATUM_SV2_SET_TARGET *m, unsigned char *out, size_t cap);

// --- decoders: parse exactly len bytes; false on truncation, trailing bytes or invalid values ---
bool datum_sv2_decode_setup_connection(const unsigned char *in, size_t len, T_DATUM_SV2_SETUP_CONNECTION *m);
bool datum_sv2_decode_setup_connection_success(const unsigned char *in, size_t len, T_DATUM_SV2_SETUP_CONNECTION_SUCCESS *m);
bool datum_sv2_decode_open_channel(const unsigned char *in, size_t len, bool extended, T_DATUM_SV2_OPEN_CHANNEL *m);
bool datum_sv2_decode_open_channel_success(const unsigned char *in, size_t len, bool extended, T_DATUM_SV2_OPEN_CHANNEL_SUCCESS *m);
bool datum_sv2_decode_update_channel(const unsigned char *in, size_t len, T_DATUM_SV2_UPDATE_CHANNEL *m);
bool datum_sv2_decode_channel_code(const unsigned char *in, size_t len, T_DATUM_SV2_CHANNEL_CODE *m);
bool datum_sv2_decode_submit_shares(const unsigned char *in, size_t len, bool extended, T_DATUM_SV2_SUBMIT_SHARES *m);
bool datum_sv2_decode_submit_shares_success(const unsigned char *in, size_t len, T_DATUM_SV2_SUBMIT_SHARES_SUCCESS *m);
bool datum_sv2_decode_new_mining_job(const unsigned char *in, size_t len, bool extended, T_DATUM_SV2_NEW_MINING_JOB *m);
bool datum_sv2_decode_set_new_prev_hash(const unsigned char *in, size_t len, T_DATUM_SV2_SET_NEW_PREV_HASH *m);
bool datum_sv2_decode_set_target(const unsigned char *in, size_t len, T_DATUM_SV2_SET_TARGET *m);

bool datum_sv2_str_set(T_DATUM_SV2_STR *s, const char *v);

#endif
