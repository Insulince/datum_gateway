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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_pow.h"
#include "datum_stratum_dupes.h"
#include "datum_sv2.h"
#include "datum_utils.h"

// A test client: drives a server connection through datum_sv2_conn_feed the
// way the socket glue does, holding unconsumed bytes between reads.
typedef struct {
	T_DATUM_SV2_CONN conn;
	T_DATUM_SV2_CTX ctx;
	T_DATUM_SV2_NOISE_SESSION s;
	unsigned char in[8192]; // server's receive buffer
	size_t in_len;
	unsigned char out[65536]; // what the server sent, not yet read by the client
	size_t out_len;
	bool closed;
} T_TC;

static T_DATUM_SV2_NOISE_IDENTITY tc_id;
static T_TC tc_a, tc_b; // large; keep off the stack

static void tc_deliver(T_TC *t, const unsigned char *b, size_t n, size_t step) {
	for (size_t i = 0; i < n && !t->closed; i += step) {
		size_t k = (n - i < step) ? n - i : step, consumed = 0;
		T_DATUM_SV2_SINK sink = { .buf = &t->out[t->out_len], .cap = sizeof(t->out) - t->out_len, .len = 0 };
		memcpy(&t->in[t->in_len], &b[i], k);
		t->in_len += k;
		if (!datum_sv2_conn_feed(&t->conn, &t->ctx, t->in, t->in_len, &consumed, &sink)) t->closed = true;
		t->out_len += sink.len;
		memmove(t->in, &t->in[consumed], t->in_len - consumed);
		t->in_len -= consumed;
	}
}

static bool tc_connect(T_TC *t, size_t step, const T_DATUM_SV2_WORK *work) {
	T_DATUM_SV2_NOISE_INITIATOR st;
	unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN];

	memset(t, 0, sizeof(*t));
	t->ctx.id = &tc_id;
	t->ctx.now = 1760000000;
	t->ctx.now_tsms = 1000000;
	t->ctx.min_diff = 16384;
	t->ctx.target_shares_min = 8;
	t->ctx.quickdiff_count = 8;
	t->ctx.quickdiff_delta = 8;
	t->ctx.work = work;
	datum_sv2_conn_init(&t->conn, datum_sv2_session_base(1, 5), t->ctx.now_tsms);
	if (!datum_sv2_noise_initiate(&st, act1)) return false;
	tc_deliver(t, act1, sizeof(act1), step);
	if (t->out_len != DATUM_SV2_NOISE_ACT2_LEN) return false;
	if (!datum_sv2_noise_initiator_finish(&st, t->out, tc_id.authority_pk_xonly, t->ctx.now, &t->s)) return false;
	t->out_len = 0;
	return true;
}

static void tc_send(T_TC *t, uint8_t msg_type, const unsigned char *pl, size_t len, size_t step) {
	unsigned char header[DATUM_SV2_FRAME_HEADER_LEN], wire[2048];
	size_t n = 0;
	datum_sv2_header_encode(header, 0, datum_sv2_msg_is_channel_msg(msg_type), msg_type, (uint32_t)len);
	if (datum_test(datum_sv2_noise_encrypt_frame(&t->s.encrypt, header, pl, len, wire, &n))) {
		tc_deliver(t, wire, n, step);
	}
}

// read the next frame the server sent
static bool tc_recv(T_TC *t, T_DATUM_SV2_FRAME_HEADER *h, unsigned char *pl) {
	unsigned char header[DATUM_SV2_FRAME_HEADER_LEN];
	size_t ct;
	if (t->out_len < DATUM_SV2_NOISE_HEADER_CT_LEN) return false;
	if (!datum_sv2_noise_decrypt_header(&t->s.decrypt, t->out, header)) return false;
	datum_sv2_header_decode(header, h);
	ct = datum_sv2_noise_payload_ct_len(h->length);
	if (t->out_len < DATUM_SV2_NOISE_HEADER_CT_LEN + ct) return false;
	if (!datum_sv2_noise_decrypt_payload(&t->s.decrypt, &t->out[DATUM_SV2_NOISE_HEADER_CT_LEN], h->length, pl)) return false;
	memmove(t->out, &t->out[DATUM_SV2_NOISE_HEADER_CT_LEN + ct], t->out_len - DATUM_SV2_NOISE_HEADER_CT_LEN - ct);
	t->out_len -= DATUM_SV2_NOISE_HEADER_CT_LEN + ct;
	return true;
}

static void tc_setup(T_TC *t, uint32_t flags, size_t step) {
	T_DATUM_SV2_SETUP_CONNECTION m = { .protocol = DATUM_SV2_PROTOCOL_MINING, .min_version = 2, .max_version = 2, .flags = flags, .endpoint_port = 23336 };
	unsigned char pl[1024];
	datum_sv2_str_set(&m.endpoint_host, "127.0.0.1");
	datum_sv2_str_set(&m.vendor, "test-vendor");
	datum_sv2_str_set(&m.firmware, "test-fw");
	tc_send(t, DATUM_SV2_MSG_SETUP_CONNECTION, pl, datum_sv2_encode_setup_connection(&m, pl, sizeof(pl)), step);
}

static void tc_open_hr(T_TC *t, bool extended, uint32_t request_id, uint16_t min_extranonce, const unsigned char max_target[32], float hash_rate) {
	T_DATUM_SV2_OPEN_CHANNEL m = { .extended = extended, .request_id = request_id, .nominal_hash_rate = hash_rate, .min_extranonce_size = min_extranonce };
	unsigned char pl[512];
	datum_sv2_str_set(&m.user_identity, "bc1qtest.worker1");
	memcpy(m.max_target, max_target, 32);
	tc_send(t, extended ? DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL : DATUM_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL, pl, datum_sv2_encode_open_channel(&m, pl, sizeof(pl)), 7);
}

static void tc_open(T_TC *t, bool extended, uint32_t request_id, uint16_t min_extranonce, const unsigned char max_target[32]) {
	tc_open_hr(t, extended, request_id, min_extranonce, max_target, 1e14f);
}

// extended submits carry an 8-byte extranonce
static void tc_submit_x(T_TC *t, bool extended, uint32_t channel_id, uint32_t seq, uint32_t job_id, uint64_t nonce, uint64_t ntime) {
	T_DATUM_SV2_SUBMIT_SHARES m = { .extended = extended, .channel_id = channel_id, .sequence_number = seq, .job_id = job_id, .nonce = nonce, .ntime = ntime };
	unsigned char pl[128];
	if (extended) {
		m.extranonce.len = 8;
		for (int i = 0; i < 8; i++) m.extranonce.b[i] = (unsigned char)(0xc0 + i);
	}
	tc_send(t, extended ? DATUM_SV2_MSG_SUBMIT_SHARES_EXTENDED : DATUM_SV2_MSG_SUBMIT_SHARES_STANDARD, pl, datum_sv2_encode_submit_shares(&m, pl, sizeof(pl)), 64);
}

static void tc_submit(T_TC *t, uint32_t channel_id, uint32_t seq) {
	tc_submit_x(t, true, channel_id, seq, 1, 1, 1760000000);
}

// the error code of a SubmitShares.Error payload
static bool share_error_is(const unsigned char *pl, const char *code) {
	size_t n = strlen(code);
	return pl[8] == n && 0 == memcmp(&pl[9], code, n);
}

static void datum_sv2_tests_session_ids(void) {
	// SV1 IDs are ((thread << 22) | client) ^ 0xB10CF00D with thread < 64; SV2 IDs never collide with them
	for (int tid = 0; tid < 64; tid += 7) {
		for (int cid = 0; cid < 4096; cid += 511) {
			uint32_t v2 = datum_sv2_session_base(tid, cid);
			datum_test((v2 >> 22) >= 0x200);
			datum_test(((((uint32_t)cid) | ((uint32_t)tid << 22)) >> 22) < 0x40);
			datum_test((v2 & 0x3FF) == 0); // room for the channel slot
			datum_test(datum_sv2_session_base(tid, cid + 1) != v2 || cid + 1 >= 4096);
		}
	}
	datum_test(datum_sv2_session_base(1, 5) != datum_sv2_session_base(2, 5));
}

static void datum_sv2_tests_diff_for_hashrate(void) {
	// 1e14 H/s at 8 shares/min: 1e14 * 60 / (8 * 2^32) = 174622 -> 131072
	datum_test(datum_sv2_diff_for_hashrate(1e14f, 8, 16384) == 131072);
	datum_test(datum_sv2_diff_for_hashrate(1e9f, 8, 16384) == 16384); // floor
	datum_test(datum_sv2_diff_for_hashrate(0.0f, 8, 16384) == 16384);
	datum_test(datum_sv2_diff_for_hashrate(1e30f, 8, 1) == (1ULL << 62)); // ceiling
}

static void datum_sv2_tests_min_diff(void) {
	// SV1's floor, raised to the pool's minimum on DATUM jobs, as a power of two never below either
	datum_test(datum_sv2_min_diff(16384, 1 << 20, true) == (1 << 20));
	datum_test(datum_sv2_min_diff(16384, 1 << 20, false) == 16384);
	datum_test(datum_sv2_min_diff(16384, 100000, true) == 131072);
	datum_test(datum_sv2_min_diff(100000, 0, false) == 131072);
	datum_test(datum_sv2_min_diff(0, 0, false) == 1);
}

static void datum_sv2_tests_handshake_and_channels(void) {
	T_TC *t = &tc_a;
	T_DATUM_SV2_FRAME_HEADER h;
	unsigned char pl[4096], max_target[32], want_target[32], lower[32];
	T_DATUM_SV2_SETUP_CONNECTION_SUCCESS ss;
	T_DATUM_SV2_OPEN_CHANNEL_SUCCESS os, os2;
	T_DATUM_SV2_SET_TARGET st;

	memset(max_target, 0xff, 32);
	datum_blake2b_share_target(want_target, floorPoT(131072)); // from the advertised 1e14 H/s

	// one byte at a time exercises every partial-read path; no work yet
	datum_test(tc_connect(t, 1, NULL));
	tc_setup(t, 0, 1);
	datum_test(!t->closed && t->conn.state == DATUM_SV2_READY);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SETUP_CONNECTION_SUCCESS && !h.channel_msg);
	datum_test(datum_sv2_decode_setup_connection_success(pl, h.length, &ss));
	datum_test(ss.used_version == 2 && ss.flags == 0);
	datum_test(0 == strcmp(t->conn.vendor, "test-vendor"));

	tc_open(t, true, 41, 8, max_target);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS);
	datum_test(datum_sv2_decode_open_channel_success(pl, h.length, true, &os));
	datum_test(os.request_id == 41 && os.channel_id == 1 && os.extranonce_size == 8 && os.extranonce_prefix.len == 4);
	datum_test(0 == memcmp(os.target, want_target, 32));
	datum_test(t->out_len == 0); // no work, so no job follows
	{
		uint32_t sid = (datum_sv2_session_base(1, 5) | 0) ^ 0xB10CF00D;
		unsigned char be[4] = { sid >> 24, sid >> 16, sid >> 8, sid };
		datum_test(0 == memcmp(os.extranonce_prefix.b, be, 4));
	}

	// a second channel gets its own id and extranonce prefix
	tc_open(t, true, 42, 4, max_target);
	datum_test(tc_recv(t, &h, pl) && datum_sv2_decode_open_channel_success(pl, h.length, true, &os2));
	datum_test(os2.channel_id == 2 && 0 != memcmp(os2.extranonce_prefix.b, os.extranonce_prefix.b, 4));

	// a max_target no difficulty we serve can meet is refused
	memset(lower, 0, 32);
	lower[20] = 0x01;
	tc_open(t, true, 46, 8, lower);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_OPEN_MINING_CHANNEL_ERROR);
	
	// a max_target below our difficulty raises the channel's difficulty to fit
	memset(lower, 0, 32);
	lower[24] = 0x01;
	tc_open(t, true, 43, 8, lower);
	datum_test(tc_recv(t, &h, pl) && datum_sv2_decode_open_channel_success(pl, h.length, true, &os2));
	datum_test(compare_hashes(os2.target, lower) <= 0);

	// a standard channel gets the whole 12-byte extranonce from us
	tc_open(t, false, 44, 0, max_target);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS);
	datum_test(datum_sv2_decode_open_channel_success(pl, h.length, false, &os2) && os2.extranonce_prefix.len == 12);
	
	// oversized extranonce requests are refused, the connection stays up
	tc_open(t, true, 45, 9, max_target);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_OPEN_MINING_CHANNEL_ERROR);
	datum_test(!t->closed);

	// lowering max_target below the current target must produce SetTarget
	{
		T_DATUM_SV2_UPDATE_CHANNEL u = { .channel_id = 1, .nominal_hash_rate = 2e14f };
		unsigned char b[128];
		memcpy(u.max_target, lower, 32);
		tc_send(t, DATUM_SV2_MSG_UPDATE_CHANNEL, b, datum_sv2_encode_update_channel(&u, b, sizeof(b)), 5);
		datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SET_TARGET && h.channel_msg);
		datum_test(datum_sv2_decode_set_target(pl, h.length, &st) && st.channel_id == 1 && compare_hashes(st.maximum_target, lower) <= 0);
		// a new nominal hashrate retargets the channel, as on opening
		memset(u.max_target, 0xff, 32);
		u.nominal_hash_rate = 1e16f;
		tc_send(t, DATUM_SV2_MSG_UPDATE_CHANNEL, b, datum_sv2_encode_update_channel(&u, b, sizeof(b)), 5);
		datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SET_TARGET && datum_sv2_decode_set_target(pl, h.length, &st));
		datum_test(datum_blake2b_share_target(want_target, floorPoT(datum_sv2_diff_for_hashrate(1e16f, 8, 16384))) && 0 == memcmp(st.maximum_target, want_target, 32));
		u.channel_id = 99;
		tc_send(t, DATUM_SV2_MSG_UPDATE_CHANNEL, b, datum_sv2_encode_update_channel(&u, b, sizeof(b)), 5);
		datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_UPDATE_CHANNEL_ERROR);
	}

	// no job was ever sent, so shares name an unknown job
	tc_submit(t, 1, 7);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SUBMIT_SHARES_ERROR && h.channel_msg);
	datum_test(pl[4] == 7 && share_error_is(pl, "invalid-job-id"));
	{
		T_DATUM_SV2_CHANNEL_CODE c = { .channel_id = 1 };
		unsigned char b[64];
		datum_sv2_str_set(&c.code, "bye");
		tc_send(t, DATUM_SV2_MSG_CLOSE_CHANNEL, b, datum_sv2_encode_channel_code(&c, b, sizeof(b)), 3);
	}
	tc_submit(t, 1, 8);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "invalid-channel-id"));
	datum_test(!t->closed && t->out_len == 0);

	// a second SetupConnection is a protocol violation
	tc_setup(t, 0, 50);
	datum_test(t->closed);
}

static void datum_sv2_tests_rejections(void) {
	T_TC *t = &tc_a;
	T_DATUM_SV2_FRAME_HEADER h;
	unsigned char pl[4096], max_target[32];

	memset(max_target, 0xff, 32);

	// work selection (SV2 Job Declaration) is refused with the flags we do not support, then closed
	datum_test(tc_connect(t, 64, NULL));
	tc_setup(t, DATUM_SV2_FLAG_REQUIRES_WORK_SELECTION, 64);
	datum_test(t->closed);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SETUP_CONNECTION_ERROR);
	datum_test(pl[0] == DATUM_SV2_FLAG_REQUIRES_WORK_SELECTION);

	// XBT work has no version field, so a device that requires version rolling cannot be served
	datum_test(tc_connect(t, 64, NULL));
	tc_setup(t, DATUM_SV2_FLAG_REQUIRES_VERSION_ROLLING | DATUM_SV2_FLAG_REQUIRES_STANDARD_JOBS, 64);
	datum_test(t->closed);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SETUP_CONNECTION_ERROR);
	datum_test(pl[0] == DATUM_SV2_FLAG_REQUIRES_VERSION_ROLLING);
	
	// a device that requires standard jobs is served, but may not open an extended channel
	datum_test(tc_connect(t, 64, NULL));
	tc_setup(t, DATUM_SV2_FLAG_REQUIRES_STANDARD_JOBS, 64);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SETUP_CONNECTION_SUCCESS);
	tc_open(t, true, 1, 8, max_target);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_OPEN_MINING_CHANNEL_ERROR && !t->closed);

	// anything before SetupConnection closes the connection
	datum_test(tc_connect(t, 64, NULL));
	tc_open(t, true, 1, 8, max_target);
	datum_test(t->closed);

	// a frame header announcing more than we accept closes the connection
	datum_test(tc_connect(t, 64, NULL));
	{
		unsigned char header[DATUM_SV2_FRAME_HEADER_LEN], ct[DATUM_SV2_NOISE_HEADER_CT_LEN];
		size_t n;
		datum_sv2_header_encode(header, 0, false, DATUM_SV2_MSG_SETUP_CONNECTION, DATUM_SV2_MAX_IN_PAYLOAD + 1);
		datum_test(datum_sv2_noise_encrypt_frame(&t->s.encrypt, header, NULL, 0, ct, &n));
		tc_deliver(t, ct, n, 64);
		datum_test(t->closed);
	}

	// a tampered frame closes the connection
	datum_test(tc_connect(t, 64, NULL));
	{
		unsigned char header[DATUM_SV2_FRAME_HEADER_LEN], wire[256];
		size_t n;
		datum_sv2_header_encode(header, 0, false, DATUM_SV2_MSG_SETUP_CONNECTION, 4);
		datum_test(datum_sv2_noise_encrypt_frame(&t->s.encrypt, header, (const unsigned char *)"abcd", 4, wire, &n));
		wire[n - 1] ^= 1;
		tc_deliver(t, wire, n, 64);
		datum_test(t->closed);
	}

	// frames of unknown extensions are ignored
	datum_test(tc_connect(t, 64, NULL));
	tc_setup(t, 0, 64);
	datum_test(tc_recv(t, &h, pl));
	{
		unsigned char header[DATUM_SV2_FRAME_HEADER_LEN], wire[256];
		size_t n;
		datum_sv2_header_encode(header, 0x4001, false, 0x01, 4);
		datum_test(datum_sv2_noise_encrypt_frame(&t->s.encrypt, header, (const unsigned char *)"abcd", 4, wire, &n));
		tc_deliver(t, wire, n, 64);
		datum_test(!t->closed && t->out_len == 0);
	}
}

// --- jobs and shares, against fabricated stratum jobs ---

static T_DATUM_STRATUM_JOB job_a, job_b;
static T_DATUM_TEMPLATE_DATA tmpl_a, tmpl_b;

// A job as the stratum code leaves it: coinbases with the share-difficulty byte at offset 50,
// the template time the commitment carries, and zero time bytes (time offset rolling on, so
// the gateway bounds what a share sends back)
static void make_job(T_DATUM_STRATUM_JOB *j, T_DATUM_TEMPLATE_DATA *tm, int global_index, unsigned char seed) {
	memset(j, 0, sizeof(*j));
	memset(tm, 0, sizeof(*tm));
	j->global_index = global_index;
	memcpy(j->job_id, "0123456789abcde", 15);
	j->job_id[15] = (char)('0' + seed % 10);
	for (int i = 0; i < 32; i++) j->prevhash_bin[i] = (unsigned char)(seed + i);
	j->version_uint = 0x20000000;
	j->nbits_uint = 0x1d00ffff;
	pk_u32le(j->nbits_bin, 0, j->nbits_uint);
	nbits_to_target(j->nbits_uint, j->block_target);
	strcpy(j->ntime, "0000000000000000");
	j->blake2b_time_on_wire = 1760062304;
	j->blake2b_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	j->block_template = tm;
	j->coinbase[0].coinb1_len = 60;
	j->coinbase[0].coinb2_len = 20;
	j->coinbase[4].coinb1_len = 60;
	j->coinbase[4].coinb2_len = 70;
	j->subsidy_only_coinbase.coinb1_len = 60;
	j->subsidy_only_coinbase.coinb2_len = 30;
	for (int i = 0; i < 60; i++) {
		j->coinbase[0].coinb1_bin[i] = (unsigned char)(seed * 5 + i);
		j->coinbase[4].coinb1_bin[i] = (unsigned char)(seed * 11 + i);
		j->subsidy_only_coinbase.coinb1_bin[i] = (unsigned char)(seed * 7 + i);
	}
	for (int i = 0; i < 20; i++) j->coinbase[0].coinb2_bin[i] = (unsigned char)(0x40 + i);
	for (int i = 0; i < 70; i++) j->coinbase[4].coinb2_bin[i] = (unsigned char)(0xb0 + i);
	for (int i = 0; i < 30; i++) j->subsidy_only_coinbase.coinb2_bin[i] = (unsigned char)(0x20 + i);
	j->target_pot_index = 50;
	j->tsms = 1000000;
	j->job_state = JOB_STATE_FULL_NORMAL_WAIT_COINBASER;
	tm->mintime = 1760000000;
	tm->curtime = 1760062304;
	tm->version = 0x20000000;
	tm->height = 961700;
	tm->bits_uint = j->nbits_uint;
	tm->txn_count = 2;
	memcpy(tm->previousblockhash_bin, j->prevhash_bin, 32);
	global_cur_stratum_jobs[global_index] = j;
}

// full_coinbase: the pool's coinbase outputs are in; subsidy_only: empty work for a new block
static void set_work(T_DATUM_SV2_WORK *w, T_DATUM_STRATUM_JOB *j, bool full_coinbase, bool subsidy_only) {
	w->job = j;
	w->full_coinbase = full_coinbase;
	w->subsidy_only = subsidy_only;
	memcpy(w->prevhash, j->prevhash_bin, 32);
}

static void tc_push_work(T_TC *t, bool new_prevhash) {
	T_DATUM_SV2_SINK sink = { .buf = &t->out[t->out_len], .cap = sizeof(t->out) - t->out_len, .len = 0 };
	datum_test(datum_sv2_conn_send_work(&t->conn, &t->ctx, new_prevhash, &sink));
	t->out_len += sink.len;
}

static void tc_tick(T_TC *t) {
	T_DATUM_SV2_SINK sink = { .buf = &t->out[t->out_len], .cap = sizeof(t->out) - t->out_len, .len = 0 };
	datum_test(datum_sv2_conn_tick(&t->conn, &t->ctx, &sink));
	t->out_len += sink.len;
}

static T_DATUM_SV2_CHANNEL *tc_channel(T_TC *t, uint32_t channel_id) {
	for (int i = 0; i < DATUM_SV2_MAX_CHANNELS; i++) {
		if (t->conn.channels[i].open && t->conn.channels[i].channel_id == channel_id) return &t->conn.channels[i];
	}
	return NULL;
}

static T_DATUM_SV2_JOB_REF *tc_job_ref(T_DATUM_SV2_CHANNEL *ch, uint32_t job_id) {
	for (int i = 0; ch && i < DATUM_SV2_JOB_REFS; i++) {
		if (ch->jobs[i].used && ch->jobs[i].job_id == job_id) return &ch->jobs[i];
	}
	return NULL;
}

// Read a job and say whether it is the one expected: the message type matches the channel, as on the wire
static bool tc_recv_job(T_TC *t, bool extended, T_DATUM_SV2_NEW_MINING_JOB *job) {
	T_DATUM_SV2_FRAME_HEADER h;
	unsigned char pl[512];
	if (!tc_recv(t, &h, pl) || h.extension_type != 0 || !h.channel_msg) return false;
	if (h.msg_type != (extended ? DATUM_SV2_MSG_NEW_EXTENDED_MINING_JOB : DATUM_SV2_MSG_NEW_MINING_JOB)) return false;
	return datum_sv2_decode_new_mining_job(pl, h.length, extended, job);
}

static bool tc_recv_prevhash(T_TC *t, T_DATUM_SV2_SET_NEW_PREV_HASH *p) {
	T_DATUM_SV2_FRAME_HEADER h;
	unsigned char pl[512];
	return tc_recv(t, &h, pl) && h.channel_msg && h.msg_type == DATUM_SV2_MSG_SET_NEW_PREV_HASH && datum_sv2_decode_set_new_prev_hash(pl, h.length, p);
}

// What a miner builds from a job and its time bytes, straight from doc/sv2_xbt.md, versus what the gateway checks
static void check_agreement(T_TC *t, const T_DATUM_SV2_NEW_MINING_JOB *job, const T_DATUM_SV2_SET_NEW_PREV_HASH *snph, uint64_t ntime, const T_DATUM_SV2_OPEN_CHANNEL_SUCCESS *os) {
	T_DATUM_SV2_SUBMIT_SHARES share = { .extended = job->extended, .channel_id = os->channel_id, .job_id = job->job_id, .nonce = 0x1122334455667788ULL, .ntime = ntime + 7 };
	unsigned char root[32], leaf[52], miner_work[80], gw_work[80], gw_cb[MAX_COINBASE_TXN_SIZE_BYTES], en[12], want_commitment[32];
	size_t gw_len = 0;
	T_DATUM_SV2_CHANNEL *ch = tc_channel(t, os->channel_id);
	T_DATUM_SV2_JOB_REF *ref = tc_job_ref(ch, job->job_id);

	if (!datum_test(ch != NULL && ref != NULL)) return;
	if (job->extended) {
		share.extranonce.len = 8;
		for (int i = 0; i < 8; i++) share.extranonce.b[i] = (unsigned char)(0xc0 + i);
		// merkle_root = BLAKE2b-256(0x00 || 0x000000 || commitment || 0x00000000 || extranonce)
		memset(leaf, 0, sizeof(leaf));
		memcpy(&leaf[4], job->root, 32);
		memcpy(&leaf[40], os->extranonce_prefix.b, 4);
		memcpy(&leaf[44], share.extranonce.b, 8);
		datum_test(datum_blake2b_256(root, leaf, sizeof(leaf)));
		// the commitment is the job's, with the channel's difficulty in the coinbase
		{
			T_DATUM_STRATUM_JOB *j = global_cur_stratum_jobs[ref->global_index];
			const bool empty = ref->coinbase_index == DATUM_COINBASE_ID_EMPTY;
			datum_test(datum_stratum_job_blake2b_commitment(j, empty ? &j->subsidy_only_coinbase : &j->coinbase[ref->coinbase_index], empty, floorPoT(ref->diff), want_commitment, NULL));
		}
		datum_test(0 == memcmp(job->root, want_commitment, 32));
	} else {
		memcpy(root, job->root, 32);
	}
	memcpy(miner_work, snph->prev_hash, 32);
	pk_u64le(miner_work, 32, share.nonce);
	pk_u64le(miner_work, 40, share.ntime);
	memcpy(&miner_work[48], root, 32);

	datum_test(datum_sv2_share_work(ch, ref, global_cur_stratum_jobs[ref->global_index], &share, gw_work, gw_cb, &gw_len, en));
	datum_test(0 == memcmp(gw_work, miner_work, 80));
	// the hasher extranonce lives in the work, so the coinbase carries 12 zero bytes in its place
	datum_test(gw_len == 60 + 12 + (ref->coinbase_index == 4 ? 70 : ref->coinbase_index == DATUM_COINBASE_ID_EMPTY ? 30 : 20));
	for (int i = 0; i < 12; i++) datum_test(gw_cb[60 + i] == 0);
	// the coinbase carries the channel's difficulty, as DATUM requires
	datum_test(gw_cb[50] == floorPoT(ref->diff));
	datum_test(0 == memcmp(en, os->extranonce_prefix.b, job->extended ? 4 : 12));
}

static void datum_sv2_tests_jobs(void) {
	T_TC *t = &tc_b;
	T_DATUM_SV2_WORK work;
	T_DATUM_SV2_FRAME_HEADER h;
	T_DATUM_SV2_OPEN_CHANNEL_SUCCESS os, xs;
	T_DATUM_SV2_NEW_MINING_JOB nj, xj;
	T_DATUM_SV2_SET_NEW_PREV_HASH snph;
	unsigned char pl[4096], max_target[32], want_target[32];
	uint64_t ntime;
	uint32_t first_job_id;

	make_job(&job_a, &tmpl_a, 210, 3);
	make_job(&job_b, &tmpl_b, 211, 4);
	memset(max_target, 0xff, 32);
	{
		// the time bytes SV1 sends as its 16-hex ntime: the time offset, then the template time
		unsigned char b[8];
		for (int i = 0; i < 8; i++) b[i] = hex2bin_uchar(&job_a.ntime[2 * i]);
		ntime = upk_u64le(b, 0);
		datum_test(ntime == 0);
	}

	// a standard channel: its target, then a future job carrying our merkle root, then SetNewPrevHash
	set_work(&work, &job_a, true, false);
	datum_test(tc_connect(t, 64, &work));
	tc_setup(t, 0, 64);
	datum_test(tc_recv(t, &h, pl));
	tc_open(t, false, 1, 0, max_target);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS && datum_sv2_decode_open_channel_success(pl, h.length, false, &os));
	datum_test(os.extranonce_prefix.len == 12);
	datum_test(datum_blake2b_share_target(want_target, floorPoT(131072)) && 0 == memcmp(os.target, want_target, 32));
	datum_test(tc_recv_job(t, false, &nj) && nj.channel_id == os.channel_id && !nj.has_ntime_start);
	first_job_id = nj.job_id;
	datum_test(tc_recv_prevhash(t, &snph) && snph.job_id == nj.job_id && snph.ntime_start == ntime && snph.nbits == job_a.nbits_uint);
	{
		// the prev hash the hasher's work starts with
		unsigned char want_prev[32];
		datum_blake2b_prevblock_hidden(want_prev, job_a.prevhash_bin);
		datum_test(0 == memcmp(snph.prev_hash, want_prev, 32));
	}
	datum_test(tc_job_ref(tc_channel(t, os.channel_id), nj.job_id)->coinbase_index == DATUM_SV2_COINBASE);
	check_agreement(t, &nj, &snph, snph.ntime_start, &os);

	// an unmined share reaches the hash check, which comes before the time bound; the extended submit is the wrong one here
	tc_submit_x(t, false, os.channel_id, 5, nj.job_id, 1, ntime + 1);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SUBMIT_SHARES_ERROR && pl[4] == 5 && share_error_is(pl, "difficulty-too-low"));
	tc_submit_x(t, false, os.channel_id, 7, nj.job_id + 50, 1, ntime);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "invalid-job-id"));
	tc_submit_x(t, true, os.channel_id, 8, nj.job_id, 1, ntime);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "invalid-channel-id"));

	// an extended channel gets the commitment and builds the merkle root itself
	tc_open(t, true, 2, 8, max_target);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS && datum_sv2_decode_open_channel_success(pl, h.length, true, &xs));
	datum_test(xs.extranonce_prefix.len == 4 && xs.extranonce_size == 8);
	datum_test(tc_recv_job(t, true, &xj) && xj.channel_id == xs.channel_id && !xj.has_ntime_start);
	datum_test(tc_recv_prevhash(t, &snph) && snph.job_id == xj.job_id);
	check_agreement(t, &xj, &snph, snph.ntime_start, &xs);
	tc_submit_x(t, true, xs.channel_id, 10, xj.job_id, 1, ntime);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "difficulty-too-low"));
	{
		T_DATUM_SV2_SUBMIT_SHARES m = { .extended = true, .channel_id = xs.channel_id, .sequence_number = 11, .job_id = xj.job_id, .ntime = ntime, .extranonce = { .len = 4 } };
		unsigned char b[128];
		tc_send(t, DATUM_SV2_MSG_SUBMIT_SHARES_EXTENDED, b, datum_sv2_encode_submit_shares(&m, b, sizeof(b)), 64);
		datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "invalid-extranonce-size"));
	}
	tc_submit_x(t, false, xs.channel_id, 12, xj.job_id, 1, ntime);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "invalid-channel-id"));

	// new work on the same tip: jobs to mine now, carrying their time bytes; earlier jobs stay valid
	tc_push_work(t, false);
	datum_test(tc_recv_job(t, false, &nj) && nj.channel_id == os.channel_id && nj.has_ntime_start && nj.ntime_start == ntime && nj.job_id != first_job_id);
	check_agreement(t, &nj, &snph, nj.ntime_start, &os);
	datum_test(tc_recv_job(t, true, &xj) && xj.has_ntime_start);
	datum_test(t->out_len == 0); // no SetNewPrevHash
	tc_submit_x(t, false, os.channel_id, 13, first_job_id, 1, ntime);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "difficulty-too-low"));

	// a minimum raised while a channel mines steadily, such as the pool's, applies to the next job:
	// SetTarget first, then the job carrying it
	{
		T_DATUM_SV2_CHANNEL *ch = tc_channel(t, os.channel_id), *xch = tc_channel(t, xs.channel_id);
		T_DATUM_SV2_SET_TARGET st;
		const uint64_t saved_min = t->ctx.min_diff;
		t->ctx.min_diff = 1 << 20;
		tc_push_work(t, false);
		datum_test(ch->diff == (1 << 20) && xch->diff == (1 << 20));
		datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SET_TARGET && datum_sv2_decode_set_target(pl, h.length, &st));
		datum_test(datum_blake2b_share_target(want_target, floorPoT(1 << 20)) && 0 == memcmp(st.maximum_target, want_target, 32));
		datum_test(tc_recv_job(t, false, &nj) && tc_job_ref(ch, nj.job_id)->diff == (1 << 20));
		check_agreement(t, &nj, &snph, nj.ntime_start, &os);
		datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SET_TARGET);
		datum_test(tc_recv_job(t, true, &xj) && tc_job_ref(xch, xj.job_id)->diff == (1 << 20));
		datum_test(t->out_len == 0);
		t->ctx.min_diff = saved_min;
	}

	// vardiff: a minute without shares halves the difficulty. The job carrying it goes
	// first: SetTarget applies at once, and an easier target on an older job's
	// coinbase would get the miner's next shares rejected.
	{
		T_DATUM_SV2_CHANNEL *ch = tc_channel(t, os.channel_id);
		T_DATUM_SV2_SET_TARGET st;
		uint64_t before = ch->diff;
		for (int i = 0; i < DATUM_SV2_MAX_CHANNELS; i++) t->conn.channels[i].snap_tsms = t->ctx.now_tsms; // only this channel goes quiet
		ch->snap_tsms = t->ctx.now_tsms - 61000;
		tc_tick(t);
		datum_test(ch->diff == before >> 1);
		datum_test(tc_recv_job(t, false, &nj) && nj.has_ntime_start);
		check_agreement(t, &nj, &snph, nj.ntime_start, &os); // its commitment carries the new difficulty
		datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SET_TARGET && datum_sv2_decode_set_target(pl, h.length, &st));
		datum_test(datum_blake2b_share_target(want_target, floorPoT(before >> 1)) && 0 == memcmp(st.maximum_target, want_target, 32));
		datum_test(t->out_len == 0);

		// never below the floor
		ch->diff = t->ctx.min_diff;
		for (int i = 0; i < DATUM_SV2_MAX_CHANNELS; i++) t->conn.channels[i].snap_tsms = t->ctx.now_tsms;
		ch->snap_tsms = t->ctx.now_tsms - 61000;
		tc_tick(t);
		datum_test(ch->diff == t->ctx.min_diff && t->out_len == 0);
	}

	// a new block: future jobs announced with SetNewPrevHash; jobs before it are now stale
	set_work(&work, &job_b, true, false);
	tc_push_work(t, true);
	datum_test(tc_recv_job(t, false, &nj) && !nj.has_ntime_start);
	datum_test(tc_recv_prevhash(t, &snph) && snph.job_id == nj.job_id);
	{
		unsigned char want_prev[32];
		datum_blake2b_prevblock_hidden(want_prev, job_b.prevhash_bin);
		datum_test(0 == memcmp(snph.prev_hash, want_prev, 32));
	}
	check_agreement(t, &nj, &snph, snph.ntime_start, &os);
	datum_test(tc_recv_job(t, true, &xj) && !xj.has_ntime_start);
	datum_test(tc_recv_prevhash(t, &snph) && snph.job_id == xj.job_id);
	datum_test(t->out_len == 0);
	// the share checks still run on them first, as in SV1, so a block found on one is not lost:
	// this unmined share fails the hash check before it is found stale
	tc_submit_x(t, false, os.channel_id, 14, first_job_id, 1, ntime);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "difficulty-too-low"));

	// a recycled stratum job slot invalidates jobs that pointed at it
	job_b.job_id[0] = 'X';
	tc_submit_x(t, false, os.channel_id, 15, nj.job_id, 1, ntime);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "invalid-job-id"));
	job_b.job_id[0] = '0';
	job_b.job_id[10] = 'X'; // same second, later job: only the end of the id differs
	tc_submit_x(t, false, os.channel_id, 15, nj.job_id, 1, ntime);
	datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "invalid-job-id"));
	job_b.job_id[10] = 'a';

	// a new block's subsidy-only work: every channel, whatever its type, mines the empty coinbase,
	// announced with SetNewPrevHash; then the full work follows on the same block
	set_work(&work, &job_b, false, true);
	tc_push_work(t, true);
	datum_test(tc_recv_job(t, false, &nj) && !nj.has_ntime_start);
	datum_test(tc_job_ref(tc_channel(t, nj.channel_id), nj.job_id)->coinbase_index == DATUM_COINBASE_ID_EMPTY);
	datum_test(tc_recv_prevhash(t, &snph) && snph.job_id == nj.job_id);
	check_agreement(t, &nj, &snph, snph.ntime_start, &os);
	datum_test(tc_recv_job(t, true, &xj) && tc_job_ref(tc_channel(t, xj.channel_id), xj.job_id)->coinbase_index == DATUM_COINBASE_ID_EMPTY);
	datum_test(tc_recv_prevhash(t, &snph) && snph.job_id == xj.job_id);
	check_agreement(t, &xj, &snph, snph.ntime_start, &xs);
	datum_test(t->out_len == 0);
	set_work(&work, &job_b, true, false);
	tc_push_work(t, false);
	datum_test(tc_recv_job(t, false, &nj) && nj.has_ntime_start && tc_job_ref(tc_channel(t, nj.channel_id), nj.job_id)->coinbase_index == DATUM_SV2_COINBASE);
	datum_test(tc_recv_job(t, true, &xj) && tc_job_ref(tc_channel(t, xj.channel_id), xj.job_id)->coinbase_index == DATUM_SV2_COINBASE);
	datum_test(t->out_len == 0);

	// until the pool's coinbase outputs are in, jobs use coinbase 0, as SV1 does
	set_work(&work, &job_b, false, false);
	tc_push_work(t, false);
	datum_test(tc_recv_job(t, false, &nj) && tc_job_ref(tc_channel(t, nj.channel_id), nj.job_id)->coinbase_index == 0);
	check_agreement(t, &nj, &snph, nj.ntime_start, &os);

	datum_test(!t->closed);
	global_cur_stratum_jobs[210] = NULL;
	global_cur_stratum_jobs[211] = NULL;
}

static void datum_sv2_tests_idle(void) {
	T_DATUM_SV2_CONN c;
	const uint64_t t0 = 1000000;

	datum_sv2_conn_init(&c, 0, t0);
	datum_test(datum_sv2_conn_idle(&c, t0 + DATUM_SV2_HANDSHAKE_TIMEOUT * 1000, 0, 0) == NULL);
	datum_test(datum_sv2_conn_idle(&c, t0 + DATUM_SV2_HANDSHAKE_TIMEOUT * 1000 + 1, 0, 0) != NULL); // even with the idle timeouts off

	// set up, no channel yet (a proxy waiting for its first miner): only the no-shares limit applies
	c.state = DATUM_SV2_READY;
	datum_test(datum_sv2_conn_idle(&c, t0 + 7200 * 1000, 7200, 60) == NULL);
	datum_test(datum_sv2_conn_idle(&c, t0 + 7200 * 1000 + 1, 7200, 60) != NULL);
	datum_test(datum_sv2_conn_idle(&c, t0 + 100000000, 0, 60) == NULL);

	// once shares flow, the time since the last one counts
	c.shares_accepted = 1;
	c.last_share_tsms = t0 + 100000000;
	datum_test(datum_sv2_conn_idle(&c, c.last_share_tsms + 60000, 7200, 60) == NULL);
	datum_test(datum_sv2_conn_idle(&c, c.last_share_tsms + 60001, 7200, 60) != NULL);
	datum_test(datum_sv2_conn_idle(&c, c.last_share_tsms + 100000000, 7200, 0) == NULL);
}

// --- protocol edges ---

static void tc_expect_setup_error(uint8_t protocol, uint16_t min_version, uint16_t max_version, const char *code) {
	T_TC *t = &tc_a;
	T_DATUM_SV2_FRAME_HEADER h;
	T_DATUM_SV2_SETUP_CONNECTION m = { .protocol = protocol, .min_version = min_version, .max_version = max_version };
	unsigned char pl[512];
	size_t n = strlen(code);

	datum_test(tc_connect(t, 64, NULL));
	tc_send(t, DATUM_SV2_MSG_SETUP_CONNECTION, pl, datum_sv2_encode_setup_connection(&m, pl, sizeof(pl)), 64);
	datum_test(t->closed);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SETUP_CONNECTION_ERROR);
	datum_test(pl[4] == n && 0 == memcmp(&pl[5], code, n));
}

static void datum_sv2_tests_protocol_edges(void) {
	T_TC *t = &tc_a;
	T_DATUM_SV2_FRAME_HEADER h;
	unsigned char pl[4096], max_target[32], wire[4096];
	size_t n, wire_len;

	memset(max_target, 0xff, 32);

	tc_expect_setup_error(1, 2, 2, "unsupported-protocol");
	tc_expect_setup_error(DATUM_SV2_PROTOCOL_MINING, 3, 3, "protocol-version-mismatch");
	tc_expect_setup_error(DATUM_SV2_PROTOCOL_MINING, 1, 1, "protocol-version-mismatch");

	// a SetupConnection that does not decode closes the connection without a reply
	datum_test(tc_connect(t, 64, NULL));
	tc_send(t, DATUM_SV2_MSG_SETUP_CONNECTION, (const unsigned char *)"\0\2", 2, 64);
	datum_test(t->closed && t->out_len == 0);

	// so does any message that does not decode once set up
	datum_test(tc_connect(t, 64, NULL));
	tc_setup(t, 0, 64);
	datum_test(tc_recv(t, &h, pl));
	tc_send(t, DATUM_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL, (const unsigned char *)"\1\0\0\0", 4, 64);
	datum_test(t->closed);

	// unknown core messages and CloseChannel for a channel that is not open are ignored
	datum_test(tc_connect(t, 64, NULL));
	tc_setup(t, 0, 64);
	datum_test(tc_recv(t, &h, pl));
	tc_send(t, 0x70, (const unsigned char *)"abcd", 4, 64);
	{
		T_DATUM_SV2_CHANNEL_CODE c = { .channel_id = 77 };
		unsigned char b[64];
		datum_sv2_str_set(&c.code, "bye");
		tc_send(t, DATUM_SV2_MSG_CLOSE_CHANNEL, b, datum_sv2_encode_channel_code(&c, b, sizeof(b)), 64);
	}
	datum_test(!t->closed && t->out_len == 0);

	// several frames in one read are all handled, in order
	{
		T_DATUM_SV2_OPEN_CHANNEL m = { .extended = true, .nominal_hash_rate = 1e14f, .min_extranonce_size = 8 };
		T_DATUM_SV2_OPEN_CHANNEL_SUCCESS os;
		unsigned char header[DATUM_SV2_FRAME_HEADER_LEN], b[512];
		size_t len;
		memcpy(m.max_target, max_target, 32);
		datum_sv2_str_set(&m.user_identity, "bc1qtest.worker1");
		wire_len = 0;
		for (uint32_t id = 61; id <= 63; id++) {
			m.request_id = id;
			len = datum_sv2_encode_open_channel(&m, b, sizeof(b));
			datum_sv2_header_encode(header, 0, false, DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL, (uint32_t)len);
			datum_test(datum_sv2_noise_encrypt_frame(&t->s.encrypt, header, b, len, &wire[wire_len], &n));
			wire_len += n;
		}
		tc_deliver(t, wire, wire_len, wire_len);
		for (uint32_t id = 61; id <= 63; id++) {
			datum_test(tc_recv(t, &h, pl) && datum_sv2_decode_open_channel_success(pl, h.length, true, &os) && os.request_id == id);
		}
		datum_test(t->out_len == 0);
	}

	// a channel's max_target may not be raised past what we serve, nor lowered below any difficulty we serve
	{
		T_DATUM_SV2_UPDATE_CHANNEL u = { .channel_id = 1, .nominal_hash_rate = 1e14f };
		T_DATUM_SV2_CHANNEL_CODE e;
		unsigned char b[128];
		memset(u.max_target, 0, 32);
		u.max_target[20] = 0x01;
		tc_send(t, DATUM_SV2_MSG_UPDATE_CHANNEL, b, datum_sv2_encode_update_channel(&u, b, sizeof(b)), 64);
		datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_UPDATE_CHANNEL_ERROR);
		datum_test(datum_sv2_decode_channel_code(pl, h.length, &e) && e.channel_id == 1 && 0 == strcmp(e.code.s, "max-target-out-of-range"));
		datum_test(!t->closed);
	}

	// at most DATUM_SV2_MAX_CHANNELS channels per connection
	{
		T_DATUM_SV2_OPEN_CHANNEL_SUCCESS os;
		for (int i = 3; i < DATUM_SV2_MAX_CHANNELS; i++) {
			tc_open(t, true, (uint32_t)(100 + i), 8, max_target);
			datum_test(tc_recv(t, &h, pl) && datum_sv2_decode_open_channel_success(pl, h.length, true, &os));
		}
		tc_open(t, true, 200, 8, max_target);
		datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_OPEN_MINING_CHANNEL_ERROR);
		datum_test(pl[0] == 200 && pl[4] == strlen("max-channels-reached") && 0 == memcmp(&pl[5], "max-channels-reached", pl[4]));
		// closing one makes room again, and the new channel gets a fresh id
		{
			T_DATUM_SV2_CHANNEL_CODE c = { .channel_id = 2 };
			unsigned char b[64];
			datum_sv2_str_set(&c.code, "bye");
			tc_send(t, DATUM_SV2_MSG_CLOSE_CHANNEL, b, datum_sv2_encode_channel_code(&c, b, sizeof(b)), 64);
		}
		tc_open(t, true, 201, 8, max_target);
		datum_test(tc_recv(t, &h, pl) && datum_sv2_decode_open_channel_success(pl, h.length, true, &os) && os.channel_id == DATUM_SV2_MAX_CHANNELS + 1);
	}
	datum_test(!t->closed);
}

// --- sending: a client that does not drain its buffer ---

static void datum_sv2_tests_send_limits(void) {
	T_TC *t = &tc_a;
	T_DATUM_SV2_WORK work;
	T_DATUM_SV2_FRAME_HEADER h;
	unsigned char pl[4096], max_target[32], small[64];
	T_DATUM_SV2_SINK sink;

	make_job(&job_a, &tmpl_a, 212, 6);
	set_work(&work, &job_a, true, false);
	memset(max_target, 0xff, 32);

	// nothing is sent before SetupConnection
	datum_test(tc_connect(t, 64, &work));
	sink = (T_DATUM_SV2_SINK){ .buf = small, .cap = sizeof(small), .len = 0 };
	datum_test(datum_sv2_conn_send_work(&t->conn, &t->ctx, true, &sink) && sink.len == 0);
	datum_test(datum_sv2_conn_tick(&t->conn, &t->ctx, &sink) && sink.len == 0);

	// with no room for a job, sending work fails, so the socket glue drops the client
	tc_setup(t, 0, 64);
	datum_test(tc_recv(t, &h, pl));
	tc_open(t, false, 1, 0, max_target);
	datum_test(tc_recv(t, &h, pl) && tc_recv(t, &h, pl) && tc_recv(t, &h, pl) && t->out_len == 0);
	sink = (T_DATUM_SV2_SINK){ .buf = small, .cap = sizeof(small), .len = 0 };
	datum_test(!datum_sv2_conn_send_work(&t->conn, &t->ctx, false, &sink));

	// a handshake with no room for act 2 closes the connection
	{
		T_DATUM_SV2_CONN conn;
		T_DATUM_SV2_NOISE_INITIATOR st;
		unsigned char act1[DATUM_SV2_NOISE_ACT1_LEN];
		size_t consumed = 0;
		datum_sv2_conn_init(&conn, datum_sv2_session_base(0, 0), 0);
		datum_test(datum_sv2_noise_initiate(&st, act1));
		sink = (T_DATUM_SV2_SINK){ .buf = small, .cap = sizeof(small), .len = 0 };
		datum_test(!datum_sv2_conn_feed(&conn, &t->ctx, act1, sizeof(act1), &consumed, &sink));
		datum_sv2_conn_wipe(&conn);
	}

	// a job slot is reused after DATUM_SV2_JOB_REFS more jobs: shares naming the old job are refused
	{
		T_DATUM_SV2_NEW_MINING_JOB nj;
		uint32_t first;
		tc_push_work(t, false);
		datum_test(tc_recv_job(t, false, &nj));
		first = nj.job_id;
		for (int i = 0; i < DATUM_SV2_JOB_REFS; i++) {
			tc_push_work(t, false);
			datum_test(tc_recv_job(t, false, &nj));
		}
		datum_test(nj.job_id == first + DATUM_SV2_JOB_REFS);
		tc_submit_x(t, false, 1, 1, first, 1, 0);
		datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "invalid-job-id"));
		tc_submit_x(t, false, 1, 2, first + 1, 1, 0);
		datum_test(tc_recv(t, &h, pl) && share_error_is(pl, "difficulty-too-low"));
	}
	global_cur_stratum_jobs[212] = NULL;
}

// --- accepted shares, mined in advance ---

// Nonces whose work hashes below the difficulty-1 target (32 leading zero bits) for the
// jobs datum_sv2_tests_accepted builds. Recompute them with DATUM_SV2_TEST_WORK=1, which
// prints each job's work, if that job or the channel layout changes.
static const uint64_t mined_std[2] = { 88612928ULL, 5298356399ULL };
static const uint64_t mined_ext[2] = { 2872153656ULL, 9003287636ULL };

static void print_work(const char *name, T_TC *t, uint32_t channel_id, uint32_t job_id, uint64_t ntime) {
	T_DATUM_SV2_CHANNEL *ch = tc_channel(t, channel_id);
	T_DATUM_SV2_JOB_REF *ref = tc_job_ref(ch, job_id);
	T_DATUM_SV2_SUBMIT_SHARES m = { .extended = ch && !ch->standard, .channel_id = channel_id, .job_id = job_id, .ntime = ntime };
	unsigned char work[80], cb[MAX_COINBASE_TXN_SIZE_BYTES], en[12];
	size_t cb_len;
	if (!ref) return;
	if (m.extended) {
		m.extranonce.len = 8;
		for (int i = 0; i < 8; i++) m.extranonce.b[i] = (unsigned char)(0xc0 + i);
	}
	if (!datum_sv2_share_work(ch, ref, global_cur_stratum_jobs[ref->global_index], &m, work, cb, &cb_len, en)) return;
	printf("%s ", name);
	for (int i = 0; i < 80; i++) printf("%02x", work[i]);
	printf("\n");
}

// Read a SubmitShares.Success and check it acknowledges exactly this share
static bool tc_recv_share_ok(T_TC *t, uint32_t channel_id, uint32_t seq, uint64_t diff) {
	T_DATUM_SV2_FRAME_HEADER h;
	T_DATUM_SV2_SUBMIT_SHARES_SUCCESS ok;
	unsigned char pl[512];
	if (!tc_recv(t, &h, pl) || h.msg_type != DATUM_SV2_MSG_SUBMIT_SHARES_SUCCESS || !h.channel_msg) return false;
	if (!datum_sv2_decode_submit_shares_success(pl, h.length, &ok)) return false;
	return ok.channel_id == channel_id && ok.last_sequence_number == seq && ok.new_submits_accepted_count == 1 && ok.new_shares_sum == diff;
}

static bool tc_recv_share_error(T_TC *t, uint32_t seq, const char *code) {
	T_DATUM_SV2_FRAME_HEADER h;
	unsigned char pl[512];
	return tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SUBMIT_SHARES_ERROR && upk_u32le(pl, 4) == seq && share_error_is(pl, code);
}

static void datum_sv2_tests_accepted(void) {
	T_TC *t = &tc_b;
	T_DATUM_SV2_WORK work;
	T_DATUM_SV2_FRAME_HEADER h;
	T_DATUM_SV2_OPEN_CHANNEL_SUCCESS os, xs;
	T_DATUM_SV2_NEW_MINING_JOB nj, xj;
	T_DATUM_SV2_SET_NEW_PREV_HASH snph;
	T_DATUM_SV2_SET_TARGET st;
	T_DATUM_SV2_CHANNEL *ch, *xch;
	static T_DATUM_STRATUM_DUPE_ITEM items[64];
	static T_DATUM_STRATUM_DUPES dupes;
	static T_DATUM_STRATUM_THREADPOOL_DATA sdata;
	unsigned char pl[4096], max_target[32], want_target[32];
	const bool print = getenv("DATUM_SV2_TEST_WORK") != NULL;
	const uint64_t acc_count = stratum_client_accepted_share_count, acc_diff = stratum_client_accepted_share_diff;
	const uint64_t rej_count = stratum_client_rejected_share_count;
	const int saved_stale = datum_config.stratum_v1_share_stale_seconds, saved_update = datum_config.bitcoind_work_update_seconds;
	uint32_t first_std_job = 0;

	memset(items, 0, sizeof(items));
	memset(&dupes, 0, sizeof(dupes));
	memset(&sdata, 0, sizeof(sdata));
	dupes.ptr = items;
	dupes.max_items = 64;
	sdata.dupes = &dupes;
	datum_config.stratum_v1_share_stale_seconds = 120;
	datum_config.bitcoind_work_update_seconds = 40;

	make_job(&job_a, &tmpl_a, 213, 9);
	nbits_to_target(0x1b00ffff, job_a.block_target); // so these shares are not blocks; the work is unchanged
	sdata.loop_tsms = job_a.tsms;
	set_work(&work, &job_a, true, false);
	memset(max_target, 0xff, 32);

	// a device too slow for anything above difficulty 1, on a gateway whose floor is 1
	datum_test(tc_connect(t, 64, &work));
	t->ctx.min_diff = 1;
	t->ctx.sdata = &sdata;
	tc_setup(t, 0, 64);
	datum_test(tc_recv(t, &h, pl));
	tc_open_hr(t, false, 1, 0, max_target, 1.0f);
	datum_test(tc_recv(t, &h, pl) && datum_sv2_decode_open_channel_success(pl, h.length, false, &os));
	datum_test(datum_blake2b_share_target(want_target, 0) && 0 == memcmp(os.target, want_target, 32));
	datum_test(tc_recv_job(t, false, &nj) && tc_recv_prevhash(t, &snph));
	first_std_job = nj.job_id;
	tc_open_hr(t, true, 2, 8, max_target, 1.0f);
	datum_test(tc_recv(t, &h, pl) && datum_sv2_decode_open_channel_success(pl, h.length, true, &xs));
	datum_test(tc_recv_job(t, true, &xj) && tc_recv_prevhash(t, &snph));
	ch = tc_channel(t, os.channel_id);
	xch = tc_channel(t, xs.channel_id);
	if (!datum_test(ch && xch && ch->diff == 1 && xch->diff == 1)) return;

	if (print) {
		print_work("standard", t, os.channel_id, nj.job_id, snph.ntime_start);
		print_work("extended", t, xs.channel_id, xj.job_id, snph.ntime_start);
		global_cur_stratum_jobs[213] = NULL;
		return;
	}

	// a share that meets the target is accepted and acknowledged with its difficulty
	tc_submit_x(t, false, os.channel_id, 1, nj.job_id, mined_std[0], snph.ntime_start);
	datum_test(tc_recv_share_ok(t, os.channel_id, 1, 1));
	datum_test(ch->shares_accepted == 1 && ch->diff_accepted == 1 && ch->shares_rejected == 0);
	datum_test(t->conn.shares_accepted == 1 && t->conn.last_share_tsms == t->ctx.now_tsms);
	datum_test(ch->stats.last_share_tsms == t->ctx.now_tsms && ch->stats.diff_accepted[0] + ch->stats.diff_accepted[1] == 1);
	datum_test(stratum_client_accepted_share_count == acc_count + 1 && stratum_client_accepted_share_diff == acc_diff + 1);
	datum_test(datum_sv2_conn_idle(&t->conn, t->ctx.now_tsms + 1000, 1, 0) == NULL);

	// the same share again is a duplicate
	tc_submit_x(t, false, os.channel_id, 2, nj.job_id, mined_std[0], snph.ntime_start);
	datum_test(tc_recv_share_error(t, 2, "duplicate-share"));
	datum_test(ch->shares_rejected == 1 && ch->diff_rejected == 1 && stratum_client_rejected_share_count == rej_count + 1);

	// so do rejects found before the share checks run
	tc_submit_x(t, false, os.channel_id, 2, nj.job_id + 50, mined_std[0], snph.ntime_start);
	datum_test(tc_recv_share_error(t, 2, "invalid-job-id"));
	datum_test(stratum_client_rejected_share_count == rej_count + 2);

	// any other nonce misses the target
	tc_submit_x(t, false, os.channel_id, 3, nj.job_id, mined_std[0] + 1, snph.ntime_start);
	datum_test(tc_recv_share_error(t, 3, "difficulty-too-low"));

	// a valid share is still refused when its time is outside the node's limits, when its job
	// went stale, or when its block was replaced; the checks before the duplicate check run first
	tmpl_a.mintime = job_a.blake2b_time_on_wire + 1;
	tc_submit_x(t, false, os.channel_id, 4, nj.job_id, mined_std[1], snph.ntime_start);
	datum_test(tc_recv_share_error(t, 4, "invalid-timestamp"));
	tmpl_a.mintime = 1760000000;
	tmpl_a.curtime = job_a.blake2b_time_on_wire - 7201;
	tc_submit_x(t, false, os.channel_id, 5, nj.job_id, mined_std[1], snph.ntime_start);
	datum_test(tc_recv_share_error(t, 5, "invalid-timestamp"));
	tmpl_a.curtime = 1760062304;
	sdata.loop_tsms = job_a.tsms + 160001;
	tc_submit_x(t, false, os.channel_id, 6, nj.job_id, mined_std[1], snph.ntime_start);
	datum_test(tc_recv_share_error(t, 6, "stale-share"));
	sdata.loop_tsms = job_a.tsms;
	job_a.is_stale_prevblock = true;
	tc_submit_x(t, false, os.channel_id, 7, nj.job_id, mined_std[1], snph.ntime_start);
	datum_test(tc_recv_share_error(t, 7, "stale-share"));
	job_a.is_stale_prevblock = false;

	// the sixteenth quick share doubles the difficulty: SetTarget first, then a job carrying it
	ch->shares_since_snap = 15;
	ch->snap_tsms = t->ctx.now_tsms - 16000;
	tc_submit_x(t, false, os.channel_id, 8, nj.job_id, mined_std[1], snph.ntime_start);
	datum_test(tc_recv_share_ok(t, os.channel_id, 8, 1));
	datum_test(ch->diff == 2);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SET_TARGET && datum_sv2_decode_set_target(pl, h.length, &st));
	datum_test(datum_blake2b_share_target(want_target, floorPoT(2)) && 0 == memcmp(st.maximum_target, want_target, 32));
	datum_test(tc_recv_job(t, false, &nj) && nj.has_ntime_start && tc_job_ref(ch, nj.job_id)->diff == 2);
	datum_test(t->out_len == 0);

	// an extended channel's share is accepted on the same terms
	tc_submit_x(t, true, xs.channel_id, 9, xj.job_id, mined_ext[0], snph.ntime_start);
	datum_test(tc_recv_share_ok(t, xs.channel_id, 9, 1));
	datum_test(xch->shares_accepted == 1);

	// shares arriving far too fast jump the difficulty several steps at once
	xch->shares_since_snap = 7;
	xch->snap_tsms = t->ctx.now_tsms - 1000;
	tc_submit_x(t, true, xs.channel_id, 10, xj.job_id, mined_ext[1], snph.ntime_start);
	datum_test(tc_recv_share_ok(t, xs.channel_id, 10, 1));
	datum_test(xch->diff == 32);
	datum_test(tc_recv(t, &h, pl) && h.msg_type == DATUM_SV2_MSG_SET_TARGET);
	datum_test(tc_recv_job(t, true, &xj) && tc_job_ref(xch, xj.job_id)->diff == 32);
	datum_test(t->out_len == 0);
	datum_test(stratum_client_accepted_share_count == acc_count + 4);

	// the share check itself, called the way both servers call it: a target the hash misses,
	// and a coinbase too short to hold the difficulty byte
	{
		T_DATUM_SV2_SUBMIT_SHARES m = { .channel_id = os.channel_id, .job_id = 0, .nonce = mined_std[0], .ntime = snph.ntime_start };
		T_DATUM_SV2_JOB_REF *ref = NULL;
		unsigned char work80[80], cb[MAX_COINBASE_TXN_SIZE_BYTES], en[12], nonce8[8], ntime8[8], hard[32];
		size_t cb_len = 0;
		T_DATUM_SHARE_OUTCOME o;
		for (int i = 0; i < DATUM_SV2_JOB_REFS; i++) {
			if (ch->jobs[i].used && ch->jobs[i].diff == 1 && !ch->jobs[i].stale) { ref = &ch->jobs[i]; break; }
		}
		if (datum_test(ref != NULL) && datum_test(datum_sv2_share_work(ch, ref, &job_a, &m, work80, cb, &cb_len, en))) {
			T_DATUM_SHARE share = {
				.job = &job_a, .sdata = &sdata, .username = "u", .username_len = 1,
				.full_cb_txn = cb, .full_cb_len = cb_len, .cb = &job_a.coinbase[ref->coinbase_index],
				.extranonce_bin = en, .nonce8 = nonce8, .ntime8 = ntime8,
				.coinbase_index = ref->coinbase_index, .job_diff = 1, .target = hard,
			};
			pk_u64le(nonce8, 0, m.nonce);
			pk_u64le(ntime8, 0, m.ntime);
			datum_test(datum_blake2b_share_target(hard, 40));
			datum_test(datum_stratum_check_share(&share, &o) == DATUM_SHARE_HIGH_HASH);
			datum_test(!o.was_block && 0 == strcmp(o.username, "u") && upk_u32le(o.hash, 28) == 0);
			share.full_cb_len = (size_t)job_a.target_pot_index;
			datum_test(datum_stratum_check_share(&share, &o) == DATUM_SHARE_INVALID);
		}
	}

	// a username's modifier is looked for only up to its first NUL, as SV1 always has
	{
		T_DATUM_SV2_SUBMIT_SHARES m = { .channel_id = os.channel_id, .nonce = mined_std[0], .ntime = snph.ntime_start };
		T_DATUM_SV2_JOB_REF *ref = tc_job_ref(ch, first_std_job);
		unsigned char work80[80], cb[MAX_COINBASE_TXN_SIZE_BYTES], en[12], nonce8[8], ntime8[8], easy[32];
		size_t cb_len = 0;
		T_DATUM_SHARE_OUTCOME o;
		json_error_t err;
		json_t * const j_umods = JSON_LOADS("{\"x\":{\"addrA\": 1.0}}", &err);
		struct datum_username_mod *umods = NULL, * const saved_umods = datum_config.stratum_username_mod;
		datum_test(j_umods && datum_config_parse_username_mods(&umods, j_umods, false) == 1);
		json_decref(j_umods);
		if (datum_test(ref != NULL) && datum_test(datum_sv2_share_work(ch, ref, &job_a, &m, work80, cb, &cb_len, en))) {
			const T_DATUM_SHARE share = {
				.job = &job_a, .sdata = &sdata, .username = "a\0~x", .username_len = 4,
				.full_cb_txn = cb, .full_cb_len = cb_len, .cb = &job_a.coinbase[ref->coinbase_index],
				.extranonce_bin = en, .nonce8 = nonce8, .ntime8 = ntime8,
				.coinbase_index = ref->coinbase_index, .job_diff = 1, .target = easy,
			};
			pk_u64le(nonce8, 0, m.nonce);
			pk_u64le(ntime8, 0, m.ntime);
			datum_test(datum_blake2b_share_target(easy, 0));
			datum_config.stratum_username_mod = umods;
			datum_stratum_check_share(&share, &o);
			datum_test(o.username == share.username);
			datum_config.stratum_username_mod = saved_umods;
		}
		free(umods); // parsed into a single allocation
	}

	// a valid share on a job replaced by a new block is found stale after the share checks
	set_work(&work, &job_a, true, false);
	tc_push_work(t, true);
	while (tc_recv(t, &h, pl)) {}
	tc_submit_x(t, false, os.channel_id, 20, first_std_job, mined_std[1], snph.ntime_start);
	datum_test(tc_recv_share_error(t, 20, "stale-share"));

	datum_test(!t->closed);
	datum_config.stratum_v1_share_stale_seconds = saved_stale;
	datum_config.bitcoind_work_update_seconds = saved_update;
	global_cur_stratum_jobs[213] = NULL;
}

static void datum_sv2_tests_edges_of_time(void) {
	T_DATUM_SV2_CONN c;
	const uint64_t t0 = 1000000;

	// the wall clock stepping back is never mistaken for idleness
	datum_sv2_conn_init(&c, 0, t0);
	datum_test(datum_sv2_conn_idle(&c, t0 - 5000, 1, 1) == NULL);
	c.state = DATUM_SV2_READY;
	datum_test(datum_sv2_conn_idle(&c, t0 - 5000, 1, 1) == NULL);
	c.shares_accepted = 1;
	c.last_share_tsms = t0 + 10000;
	datum_test(datum_sv2_conn_idle(&c, t0, 1, 1) == NULL);

	// difficulty for a hashrate: unusable inputs fall back to the floor
	datum_test(datum_sv2_diff_for_hashrate(1e14f, 0, 1) == datum_sv2_diff_for_hashrate(1e14f, 1, 1));
	datum_test(datum_sv2_diff_for_hashrate(0.0f, 8, 0) == 1);
	datum_test(datum_sv2_diff_for_hashrate(-5.0f, 8, 64) == 64);
	datum_test(datum_sv2_diff_for_hashrate(1e14f, 8, 1u << 20) == (1u << 20)); // floor above the estimate
	datum_test(datum_sv2_diff_for_hashrate(1e14f, 8, 3) == 131072); // a floor that is not a power of two is a floor only
}

// sv2-spec 4.7 example
static void datum_sv2_tests_authority_key(void) {
	// checked when the config loads: 64 hex characters naming a valid secp256k1 secret key
	datum_test(datum_sv2_authority_key_valid("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80"));
	datum_test(datum_sv2_authority_key_valid("6162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80"));
	datum_test(!datum_sv2_authority_key_valid("0000000000000000000000000000000000000000000000000000000000000000"));
	datum_test(!datum_sv2_authority_key_valid("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")); // the group order
	datum_test(!datum_sv2_authority_key_valid("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8g"));
	datum_test(!datum_sv2_authority_key_valid("6162"));
}

static void datum_sv2_tests_authority_b58(void) {
	static const unsigned char key[32] = {
		118, 99, 112, 0, 151, 156, 28, 17, 175, 12, 48, 11, 205, 140, 127, 228,
		134, 16, 252, 233, 185, 193, 30, 61, 174, 227, 90, 224, 176, 138, 116, 85,
	};
	char b58[128];
	datum_test(datum_sv2_authority_pubkey_b58(key, b58, sizeof(b58)));
	datum_test(0 == strcmp(b58, "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh"));
}

void datum_sv2_tests(void) {
	unsigned char authority_sk[32];
	for (int i = 0; i < 32; i++) authority_sk[i] = (unsigned char)(0x61 + i);
	datum_test(datum_sv2_noise_identity_init(&tc_id, authority_sk, 3600));
	datum_sv2_tests_authority_b58();
	datum_sv2_tests_session_ids();
	datum_sv2_tests_diff_for_hashrate();
	datum_sv2_tests_min_diff();
	datum_sv2_tests_authority_key();
	datum_sv2_tests_handshake_and_channels();
	datum_sv2_tests_rejections();
	datum_sv2_tests_jobs();
	datum_sv2_tests_idle();
	datum_sv2_tests_protocol_edges();
	datum_sv2_tests_send_limits();
	datum_sv2_tests_accepted();
	datum_sv2_tests_edges_of_time();
}
