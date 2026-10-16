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

// Stratum V2 message framing and encoding

#include <stdint.h>
#include <string.h>

#include "datum_sv2_msg.h"

// --- primitive writer / reader (all multibyte values little-endian) ---

typedef struct {
	unsigned char *p;
	size_t cap;
	size_t len;
	bool err;
} T_W;

typedef struct {
	const unsigned char *p;
	size_t len;
	size_t pos;
	bool err;
} T_R;

static void w_bytes(T_W *w, const void *v, size_t n) {
	if (w->err || n > w->cap - w->len) { w->err = true; return; }
	if (n) memcpy(&w->p[w->len], v, n);
	w->len += n;
}

static void w_uint(T_W *w, uint64_t v, int n) {
	unsigned char b[8];
	for (int i = 0; i < n; i++) b[i] = (unsigned char)(v >> (8 * i));
	w_bytes(w, b, n);
}

static void w_u8(T_W *w, uint8_t v) { w_uint(w, v, 1); }
static void w_u16(T_W *w, uint16_t v) { w_uint(w, v, 2); }
static void w_u32(T_W *w, uint32_t v) { w_uint(w, v, 4); }
static void w_u64(T_W *w, uint64_t v) { w_uint(w, v, 8); }
static void w_u256(T_W *w, const unsigned char v[32]) { w_bytes(w, v, 32); }

static void w_f32(T_W *w, float f) {
	uint32_t u;
	memcpy(&u, &f, 4);
	w_u32(w, u);
}

static void w_str(T_W *w, const T_DATUM_SV2_STR *s) {
	w_u8(w, s->len);
	w_bytes(w, s->s, s->len);
}

static void w_b032(T_W *w, const T_DATUM_SV2_B032 *b) {
	if (b->len > DATUM_SV2_MAX_EXTRANONCE) { w->err = true; return; }
	w_u8(w, b->len);
	w_bytes(w, b->b, b->len);
}

static void w_option_u64(T_W *w, bool has, uint64_t v) {
	w_u8(w, has ? 1 : 0);
	if (has) w_u64(w, v);
}

static size_t w_done(const T_W *w) {
	return w->err ? 0 : w->len;
}

static const unsigned char *r_take(T_R *r, size_t n) {
	const unsigned char *p;
	if (r->err || n > r->len - r->pos) { r->err = true; return NULL; }
	p = &r->p[r->pos];
	r->pos += n;
	return p;
}

static uint64_t r_uint(T_R *r, int n) {
	const unsigned char *p = r_take(r, n);
	uint64_t v = 0;
	if (!p) return 0;
	for (int i = 0; i < n; i++) v |= (uint64_t)p[i] << (8 * i);
	return v;
}

static uint8_t r_u8(T_R *r) { return (uint8_t)r_uint(r, 1); }
static uint16_t r_u16(T_R *r) { return (uint16_t)r_uint(r, 2); }
static uint32_t r_u32(T_R *r) { return (uint32_t)r_uint(r, 4); }
static uint64_t r_u64(T_R *r) { return r_uint(r, 8); }

static void r_u256(T_R *r, unsigned char out[32]) {
	const unsigned char *p = r_take(r, 32);
	if (p) memcpy(out, p, 32); else memset(out, 0, 32);
}

// NaN, infinities and negative values (including -0.0) are protocol errors
static float r_f32(T_R *r) {
	uint32_t u = r_u32(r);
	float f;
	if ((u & 0x80000000u) || ((u >> 23) & 0xFF) == 0xFF) {
		r->err = true;
		return 0;
	}
	memcpy(&f, &u, 4);
	return f;
}

static void r_str(T_R *r, T_DATUM_SV2_STR *s) {
	const unsigned char *p;
	s->len = r_u8(r);
	p = r_take(r, s->len);
	if (p) memcpy(s->s, p, s->len); else s->len = 0;
	s->s[s->len] = 0;
}

static void r_b032(T_R *r, T_DATUM_SV2_B032 *b) {
	const unsigned char *p;
	b->len = r_u8(r);
	if (b->len > DATUM_SV2_MAX_EXTRANONCE) { r->err = true; b->len = 0; return; }
	p = r_take(r, b->len);
	if (p) memcpy(b->b, p, b->len); else b->len = 0;
}

static void r_option_u64(T_R *r, bool *has, uint64_t *v) {
	uint8_t n = r_u8(r);
	*v = 0;
	*has = false;
	if (n > 1) { r->err = true; return; }
	if (n) {
		*has = true;
		*v = r_u64(r);
	}
}

static bool r_done(const T_R *r) {
	return !r->err && r->pos == r->len;
}

// Declare the writer w or reader r every encoder and decoder below works through
#define WRITER(out, cap) T_W w = { .p = (out), .cap = (cap), .len = 0, .err = false }
#define READER(in, len) T_R r = { .p = (in), .len = (len), .pos = 0, .err = false }

// --- frame header ---

void datum_sv2_header_encode(unsigned char out[6], uint16_t extension_type, bool channel_msg, uint8_t msg_type, uint32_t length) {
	uint16_t ext = (extension_type & 0x7FFF) | (channel_msg ? DATUM_SV2_CHANNEL_MSG_BIT : 0);
	out[0] = ext & 0xFF;
	out[1] = ext >> 8;
	out[2] = msg_type;
	out[3] = length & 0xFF;
	out[4] = (length >> 8) & 0xFF;
	out[5] = (length >> 16) & 0xFF;
}

void datum_sv2_header_decode(const unsigned char in[6], T_DATUM_SV2_FRAME_HEADER *h) {
	uint16_t ext = (uint16_t)(in[0] | (in[1] << 8));
	h->extension_type = ext & 0x7FFF;
	h->channel_msg = (ext & DATUM_SV2_CHANNEL_MSG_BIT) != 0;
	h->msg_type = in[2];
	h->length = (uint32_t)in[3] | ((uint32_t)in[4] << 8) | ((uint32_t)in[5] << 16);
}

bool datum_sv2_msg_is_channel_msg(uint8_t msg_type) {
	switch (msg_type) {
		case DATUM_SV2_MSG_NEW_MINING_JOB:
		case DATUM_SV2_MSG_UPDATE_CHANNEL:
		case DATUM_SV2_MSG_UPDATE_CHANNEL_ERROR:
		case DATUM_SV2_MSG_CLOSE_CHANNEL:
		case DATUM_SV2_MSG_SUBMIT_SHARES_STANDARD:
		case DATUM_SV2_MSG_SUBMIT_SHARES_EXTENDED:
		case DATUM_SV2_MSG_SUBMIT_SHARES_SUCCESS:
		case DATUM_SV2_MSG_SUBMIT_SHARES_ERROR:
		case DATUM_SV2_MSG_NEW_EXTENDED_MINING_JOB:
		case DATUM_SV2_MSG_SET_NEW_PREV_HASH:
		case DATUM_SV2_MSG_SET_TARGET:
			return true;
		default:
			return false;
	}
}

bool datum_sv2_str_set(T_DATUM_SV2_STR *s, const char *v) {
	size_t n = strlen(v);
	if (n > 255) return false;
	s->len = (uint8_t)n;
	memcpy(s->s, v, n);
	s->s[n] = 0;
	return true;
}

// --- Common ---

size_t datum_sv2_encode_setup_connection(const T_DATUM_SV2_SETUP_CONNECTION *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u8(&w, m->protocol);
	w_u16(&w, m->min_version);
	w_u16(&w, m->max_version);
	w_u32(&w, m->flags);
	w_str(&w, &m->endpoint_host);
	w_u16(&w, m->endpoint_port);
	w_str(&w, &m->vendor);
	w_str(&w, &m->hardware_version);
	w_str(&w, &m->firmware);
	w_str(&w, &m->device_id);
	return w_done(&w);
}

bool datum_sv2_decode_setup_connection(const unsigned char *in, size_t len, T_DATUM_SV2_SETUP_CONNECTION *m) {
	READER(in, len);
	m->protocol = r_u8(&r);
	m->min_version = r_u16(&r);
	m->max_version = r_u16(&r);
	m->flags = r_u32(&r);
	r_str(&r, &m->endpoint_host);
	m->endpoint_port = r_u16(&r);
	r_str(&r, &m->vendor);
	r_str(&r, &m->hardware_version);
	r_str(&r, &m->firmware);
	r_str(&r, &m->device_id);
	return r_done(&r);
}

size_t datum_sv2_encode_setup_connection_success(const T_DATUM_SV2_SETUP_CONNECTION_SUCCESS *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u16(&w, m->used_version);
	w_u32(&w, m->flags);
	return w_done(&w);
}

bool datum_sv2_decode_setup_connection_success(const unsigned char *in, size_t len, T_DATUM_SV2_SETUP_CONNECTION_SUCCESS *m) {
	READER(in, len);
	m->used_version = r_u16(&r);
	m->flags = r_u32(&r);
	return r_done(&r);
}

size_t datum_sv2_encode_setup_connection_error(const T_DATUM_SV2_SETUP_CONNECTION_ERROR *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->flags);
	w_str(&w, &m->error_code);
	return w_done(&w);
}

// --- Mining: channels ---

size_t datum_sv2_encode_open_channel(const T_DATUM_SV2_OPEN_CHANNEL *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->request_id);
	w_str(&w, &m->user_identity);
	w_f32(&w, m->nominal_hash_rate);
	w_u256(&w, m->max_target);
	if (m->extended) w_u16(&w, m->min_extranonce_size);
	return w_done(&w);
}

bool datum_sv2_decode_open_channel(const unsigned char *in, size_t len, bool extended, T_DATUM_SV2_OPEN_CHANNEL *m) {
	READER(in, len);
	m->extended = extended;
	m->request_id = r_u32(&r);
	r_str(&r, &m->user_identity);
	m->nominal_hash_rate = r_f32(&r);
	r_u256(&r, m->max_target);
	m->min_extranonce_size = extended ? r_u16(&r) : 0;
	return r_done(&r);
}

size_t datum_sv2_encode_open_channel_success(const T_DATUM_SV2_OPEN_CHANNEL_SUCCESS *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->request_id);
	w_u32(&w, m->channel_id);
	w_u256(&w, m->target);
	if (m->extended) w_u16(&w, m->extranonce_size);
	w_b032(&w, &m->extranonce_prefix);
	w_u32(&w, m->group_channel_id);
	return w_done(&w);
}

bool datum_sv2_decode_open_channel_success(const unsigned char *in, size_t len, bool extended, T_DATUM_SV2_OPEN_CHANNEL_SUCCESS *m) {
	READER(in, len);
	m->extended = extended;
	m->request_id = r_u32(&r);
	m->channel_id = r_u32(&r);
	r_u256(&r, m->target);
	m->extranonce_size = extended ? r_u16(&r) : 0;
	r_b032(&r, &m->extranonce_prefix);
	m->group_channel_id = r_u32(&r);
	return r_done(&r);
}

size_t datum_sv2_encode_open_channel_error(const T_DATUM_SV2_OPEN_CHANNEL_ERROR *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->request_id);
	w_str(&w, &m->error_code);
	return w_done(&w);
}

size_t datum_sv2_encode_update_channel(const T_DATUM_SV2_UPDATE_CHANNEL *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->channel_id);
	w_f32(&w, m->nominal_hash_rate);
	w_u256(&w, m->max_target);
	return w_done(&w);
}

bool datum_sv2_decode_update_channel(const unsigned char *in, size_t len, T_DATUM_SV2_UPDATE_CHANNEL *m) {
	READER(in, len);
	m->channel_id = r_u32(&r);
	m->nominal_hash_rate = r_f32(&r);
	r_u256(&r, m->max_target);
	return r_done(&r);
}

size_t datum_sv2_encode_channel_code(const T_DATUM_SV2_CHANNEL_CODE *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->channel_id);
	w_str(&w, &m->code);
	return w_done(&w);
}

bool datum_sv2_decode_channel_code(const unsigned char *in, size_t len, T_DATUM_SV2_CHANNEL_CODE *m) {
	READER(in, len);
	m->channel_id = r_u32(&r);
	r_str(&r, &m->code);
	return r_done(&r);
}

// --- Mining: shares ---

size_t datum_sv2_encode_submit_shares(const T_DATUM_SV2_SUBMIT_SHARES *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->channel_id);
	w_u32(&w, m->sequence_number);
	w_u32(&w, m->job_id);
	w_u64(&w, m->nonce);
	w_u64(&w, m->ntime);
	if (m->extended) w_b032(&w, &m->extranonce);
	return w_done(&w);
}

bool datum_sv2_decode_submit_shares(const unsigned char *in, size_t len, bool extended, T_DATUM_SV2_SUBMIT_SHARES *m) {
	READER(in, len);
	m->extended = extended;
	m->channel_id = r_u32(&r);
	m->sequence_number = r_u32(&r);
	m->job_id = r_u32(&r);
	m->nonce = r_u64(&r);
	m->ntime = r_u64(&r);
	if (extended) r_b032(&r, &m->extranonce); else m->extranonce.len = 0;
	return r_done(&r);
}

size_t datum_sv2_encode_submit_shares_success(const T_DATUM_SV2_SUBMIT_SHARES_SUCCESS *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->channel_id);
	w_u32(&w, m->last_sequence_number);
	w_u32(&w, m->new_submits_accepted_count);
	w_u64(&w, m->new_shares_sum);
	return w_done(&w);
}

bool datum_sv2_decode_submit_shares_success(const unsigned char *in, size_t len, T_DATUM_SV2_SUBMIT_SHARES_SUCCESS *m) {
	READER(in, len);
	m->channel_id = r_u32(&r);
	m->last_sequence_number = r_u32(&r);
	m->new_submits_accepted_count = r_u32(&r);
	m->new_shares_sum = r_u64(&r);
	return r_done(&r);
}

size_t datum_sv2_encode_submit_shares_error(const T_DATUM_SV2_SUBMIT_SHARES_ERROR *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->channel_id);
	w_u32(&w, m->sequence_number);
	w_str(&w, &m->error_code);
	return w_done(&w);
}

// --- Mining: jobs ---

size_t datum_sv2_encode_new_mining_job(const T_DATUM_SV2_NEW_MINING_JOB *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->channel_id);
	w_u32(&w, m->job_id);
	w_option_u64(&w, m->has_ntime_start, m->ntime_start);
	w_u256(&w, m->root);
	return w_done(&w);
}

bool datum_sv2_decode_new_mining_job(const unsigned char *in, size_t len, bool extended, T_DATUM_SV2_NEW_MINING_JOB *m) {
	READER(in, len);
	m->extended = extended;
	m->channel_id = r_u32(&r);
	m->job_id = r_u32(&r);
	r_option_u64(&r, &m->has_ntime_start, &m->ntime_start);
	r_u256(&r, m->root);
	return r_done(&r);
}

size_t datum_sv2_encode_set_new_prev_hash(const T_DATUM_SV2_SET_NEW_PREV_HASH *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->channel_id);
	w_u32(&w, m->job_id);
	w_u256(&w, m->prev_hash);
	w_u64(&w, m->ntime_start);
	w_u32(&w, m->nbits);
	return w_done(&w);
}

bool datum_sv2_decode_set_new_prev_hash(const unsigned char *in, size_t len, T_DATUM_SV2_SET_NEW_PREV_HASH *m) {
	READER(in, len);
	m->channel_id = r_u32(&r);
	m->job_id = r_u32(&r);
	r_u256(&r, m->prev_hash);
	m->ntime_start = r_u64(&r);
	m->nbits = r_u32(&r);
	return r_done(&r);
}

size_t datum_sv2_encode_set_target(const T_DATUM_SV2_SET_TARGET *m, unsigned char *out, size_t cap) {
	WRITER(out, cap);
	w_u32(&w, m->channel_id);
	w_u256(&w, m->maximum_target);
	return w_done(&w);
}

bool datum_sv2_decode_set_target(const unsigned char *in, size_t len, T_DATUM_SV2_SET_TARGET *m) {
	READER(in, len);
	m->channel_id = r_u32(&r);
	r_u256(&r, m->maximum_target);
	return r_done(&r);
}
