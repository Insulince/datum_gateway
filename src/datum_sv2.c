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

// Stratum V2 Mining Protocol server for providing work to mining hardware

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_gateway.h"
#include "datum_logger.h"
#include "datum_pow.h"
#include "datum_protocol.h"
#include "datum_sockets.h"
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_sv2.h"
#include "datum_utils.h"
#include "thirdparty_base58.h"

// --- connection protocol ---

void datum_sv2_conn_init(T_DATUM_SV2_CONN *conn, uint32_t session_base, uint64_t now_tsms) {
	sodium_memzero(conn, sizeof(*conn));
	conn->state = DATUM_SV2_AWAIT_HANDSHAKE;
	conn->connect_tsms = now_tsms;
	conn->session_base = session_base;
	conn->next_channel_id = 1;
	conn->next_job_id = 1;
}

void datum_sv2_conn_wipe(T_DATUM_SV2_CONN *conn) {
	sodium_memzero(conn, sizeof(*conn));
}

uint32_t datum_sv2_session_base(int thread_id, int client_id) {
	return (1U << 31) | (((uint32_t)thread_id & 0x1FF) << 22) | (((uint32_t)client_id & 0xFFF) << 10);
}

static uint32_t channel_session_id(const T_DATUM_SV2_CONN *conn, int slot) {
	return (conn->session_base | (uint32_t)slot) ^ 0xB10CF00D;
}

// The session ID as the first 4 extranonce bytes, big-endian like SV1's extranonce1
static void session_id_bytes(uint32_t session_id, unsigned char out[4]) {
	out[0] = (unsigned char)(session_id >> 24);
	out[1] = (unsigned char)(session_id >> 16);
	out[2] = (unsigned char)(session_id >> 8);
	out[3] = (unsigned char)session_id;
}

// Milliseconds from then to now; 0 if the wall clock stepped back past then
static uint64_t ms_since(uint64_t now_tsms, uint64_t then_tsms) {
	return now_tsms > then_tsms ? now_tsms - then_tsms : 0;
}

#define DATUM_SV2_MAX_DIFF (1ULL << 62)

uint64_t datum_sv2_min_diff(uint64_t v1_min, uint64_t pool_min, bool datum_job) {
	uint64_t min = v1_min;
	uint64_t p;
	if (datum_job && pool_min > min) min = pool_min;
	if (!min) return 1;
	// rounding down would serve shares easier than the minimum asked for
	p = roundDownToPowerOfTwo_64(min);
	return p < min ? p << 1 : p;
}

uint64_t datum_sv2_diff_for_hashrate(float hash_rate, int target_shares_min, uint64_t min_diff) {
	// shares/minute at difficulty d is hash_rate * 60 / (d * 2^32)
	double d;
	uint64_t diff;
	if (target_shares_min < 1) target_shares_min = 1;
	if (!min_diff) min_diff = 1;
	if (!(hash_rate > 0)) return min_diff;
	d = (double)hash_rate * 60.0 / ((double)target_shares_min * 4294967296.0);
	if (d >= (double)DATUM_SV2_MAX_DIFF) return DATUM_SV2_MAX_DIFF;
	diff = (d < 1.0) ? 1 : roundDownToPowerOfTwo_64((uint64_t)d);
	return diff < min_diff ? min_diff : diff;
}

// Share targets are powers of two, as the SV1 server sets them
static void channel_target(uint64_t diff, unsigned char t[32]) {
	datum_blake2b_share_target(t, floorPoT(diff)); // cannot fail: floorPoT is below 64
}

// Raise diff until its target is within the channel's max_target; 0 if no difficulty we serve gets there.
static uint64_t fit_diff(uint64_t diff, const unsigned char max_target[32]) {
	unsigned char t[32];
	for (;;) {
		channel_target(diff, t);
		if (compare_hashes(t, max_target) <= 0) return diff;
		if (diff >= DATUM_SV2_MAX_DIFF) return 0;
		diff <<= 1;
	}
}

static bool send_msg(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_SINK *out, uint8_t msg_type, const unsigned char *payload, size_t len) {
	unsigned char header[DATUM_SV2_FRAME_HEADER_LEN];
	size_t need, n;

	// every message we send has fields; a zero length means the encoder ran out of room
	if (!len) return false;
	need = DATUM_SV2_NOISE_HEADER_CT_LEN + datum_sv2_noise_payload_ct_len(len);
	if (len > 0xFFFFFF || need > out->cap - out->len) return false;
	datum_sv2_header_encode(header, 0, datum_sv2_msg_is_channel_msg(msg_type), msg_type, (uint32_t)len);
	if (!datum_sv2_noise_encrypt_frame(&conn->noise.encrypt, header, payload, len, &out->buf[out->len], &n)) return false;
	out->len += n;
	return true;
}

// Encode msg into a stack buffer and queue it. If it does not fit, the calling function
// returns false, which closes the connection.
#define SEND(conn, out, type, encoder, msg) do { \
	unsigned char pl_[1024]; \
	if (!send_msg((conn), (out), (type), pl_, encoder((msg), pl_, sizeof(pl_)))) return false; \
} while (0)

static bool setup_connection_error(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_SINK *out, uint32_t flags, const char *code) {
	T_DATUM_SV2_SETUP_CONNECTION_ERROR e = { .flags = flags };
	datum_sv2_str_set(&e.error_code, code);
	SEND(conn, out, DATUM_SV2_MSG_SETUP_CONNECTION_ERROR, datum_sv2_encode_setup_connection_error, &e);
	return true;
}

// device strings are informational; keep what fits
static void str_copy_trunc(char *dst, size_t cap, const T_DATUM_SV2_STR *s) {
	size_t n = s->len < cap - 1 ? s->len : cap - 1;
	memcpy(dst, s->s, n);
	dst[n] = 0;
}

// Returns false to close the connection (any error message is already queued).
static bool handle_setup_connection(T_DATUM_SV2_CONN *conn, const unsigned char *pl, size_t len, T_DATUM_SV2_SINK *out) {
	T_DATUM_SV2_SETUP_CONNECTION m;
	T_DATUM_SV2_SETUP_CONNECTION_SUCCESS ok = { .used_version = DATUM_SV2_VERSION, .flags = 0 };
	// miners choose their own templates through DATUM, not SV2 Job Declaration, and XBT work
	// has no version field to roll
	const uint32_t unsupported = DATUM_SV2_FLAG_REQUIRES_WORK_SELECTION | DATUM_SV2_FLAG_REQUIRES_VERSION_ROLLING;

	if (!datum_sv2_decode_setup_connection(pl, len, &m)) return false;
	if (m.protocol != DATUM_SV2_PROTOCOL_MINING) {
		setup_connection_error(conn, out, 0, "unsupported-protocol");
		return false;
	}
	if (m.min_version > DATUM_SV2_VERSION || m.max_version < DATUM_SV2_VERSION) {
		setup_connection_error(conn, out, 0, "protocol-version-mismatch");
		return false;
	}
	if (m.flags & unsupported) {
		// the error names the flags that caused it
		setup_connection_error(conn, out, m.flags & unsupported, "unsupported-feature-flags");
		return false;
	}

	conn->setup_flags = m.flags;
	str_copy_trunc(conn->vendor, sizeof(conn->vendor), &m.vendor);
	str_copy_trunc(conn->firmware, sizeof(conn->firmware), &m.firmware);
	SEND(conn, out, DATUM_SV2_MSG_SETUP_CONNECTION_SUCCESS, datum_sv2_encode_setup_connection_success, &ok);
	conn->state = DATUM_SV2_READY;
	return true;
}

static T_DATUM_SV2_CHANNEL *find_channel(T_DATUM_SV2_CONN *conn, uint32_t channel_id) {
	for (int i = 0; i < DATUM_SV2_MAX_CHANNELS; i++) {
		if (conn->channels[i].open && conn->channels[i].channel_id == channel_id) return &conn->channels[i];
	}
	return NULL;
}

// The coinbase layout new jobs use: subsidy-only for a new block, then the plain coinbase
// until the pool's outputs are in, as on SV1
static uint8_t work_coinbase_index(const T_DATUM_SV2_WORK *w) {
	if (w->subsidy_only) return DATUM_COINBASE_ID_EMPTY;
	return w->full_coinbase ? DATUM_SV2_COINBASE : 0;
}

static const T_DATUM_STRATUM_COINBASE *job_coinbase(const T_DATUM_STRATUM_JOB *job, uint8_t coinbase_index) {
	return coinbase_index == DATUM_COINBASE_ID_EMPTY ? &job->subsidy_only_coinbase : &job->coinbase[coinbase_index];
}

// The channel's 12-byte extranonce: its session ID, then 8 bytes that are ours on a standard channel and the miner's on an extended one
static void channel_extranonce(const T_DATUM_SV2_CHANNEL *ch, const unsigned char *miner_part, unsigned char en[12]) {
	session_id_bytes(ch->session_id, en);
	memcpy(&en[DATUM_SV2_EXTRANONCE_PREFIX_LEN], ch->standard ? ch->extranonce : miner_part, DATUM_SV2_EXTRANONCE_SIZE);
}

// The 8 time bytes of a job's work: what the SV1 server sends as its 16-hex ntime
static uint64_t job_ntime(const T_DATUM_STRATUM_JOB *job) {
	unsigned char t[8];
	if (strlen(job->ntime) != 16) return 0;
	for (int i = 0; i < 8; i++) t[i] = hex2bin_uchar(&job->ntime[2 * i]);
	return upk_u64le(t, 0);
}

// Send the current work to one channel, as a future job when announce_prevhash is set (followed by SetNewPrevHash).
static bool send_channel_job(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_CHANNEL *ch, const T_DATUM_SV2_CTX *ctx, bool announce_prevhash, T_DATUM_SV2_SINK *out) {
	const T_DATUM_SV2_WORK *w = ctx->work;
	T_DATUM_SV2_JOB_REF *ref;
	T_DATUM_SV2_NEW_MINING_JOB m;
	unsigned char commitment[32];
	uint8_t coinbase_index;

	if (!w || !w->job) return true; // nothing to mine yet
	announce_prevhash = announce_prevhash || ch->need_prevhash;
	coinbase_index = work_coinbase_index(w);
	// DATUM encodes each share's power-of-two difficulty in the coinbase, which the commitment covers
	if (!datum_stratum_job_blake2b_commitment(w->job, job_coinbase(w->job, coinbase_index), coinbase_index == DATUM_COINBASE_ID_EMPTY, floorPoT(ch->diff), commitment, NULL)) {
		DLOG_ERROR("Could not build the work commitment for Stratum V2 channel %u; no job sent", (unsigned)ch->channel_id);
		return true;
	}

	ref = &ch->jobs[ch->next_job_ref++ % DATUM_SV2_JOB_REFS];
	ref->used = true;
	ref->stale = false;
	ref->job_id = conn->next_job_id++;
	ref->global_index = (uint16_t)w->job->global_index;
	memcpy(ref->stratum_job_id, w->job->job_id, sizeof(ref->stratum_job_id));
	ref->coinbase_index = coinbase_index;
	ref->diff = ch->diff;

	memset(&m, 0, sizeof(m));
	m.extended = !ch->standard;
	m.channel_id = ch->channel_id;
	m.job_id = ref->job_id;
	m.has_ntime_start = !announce_prevhash;
	if (m.has_ntime_start) m.ntime_start = job_ntime(w->job);
	if (ch->standard) {
		// header-only mining: the extranonce is ours, so send the merkle root it makes of the commitment
		unsigned char en[DATUM_SV2_EXTRANONCE_PREFIX_LEN + DATUM_SV2_EXTRANONCE_SIZE];
		channel_extranonce(ch, NULL, en);
		if (!datum_blake2b_work_root(m.root, commitment, en)) return false;
	} else {
		memcpy(m.root, commitment, 32);
	}
	SEND(conn, out, ch->standard ? DATUM_SV2_MSG_NEW_MINING_JOB : DATUM_SV2_MSG_NEW_EXTENDED_MINING_JOB, datum_sv2_encode_new_mining_job, &m);

	if (announce_prevhash) {
		// the hasher's prev hash, and the time bytes the future job is mined with
		T_DATUM_SV2_SET_NEW_PREV_HASH p = { .channel_id = ch->channel_id, .job_id = ref->job_id, .ntime_start = job_ntime(w->job), .nbits = w->job->nbits_uint };
		datum_blake2b_prevblock_hidden(p.prev_hash, w->job->prevhash_bin);
		ch->need_prevhash = false;
		// every job before the new prev_hash is stale
		for (int i = 0; i < DATUM_SV2_JOB_REFS; i++) {
			if (&ch->jobs[i] != ref) ch->jobs[i].stale = true;
		}
		SEND(conn, out, DATUM_SV2_MSG_SET_NEW_PREV_HASH, datum_sv2_encode_set_new_prev_hash, &p);
	}
	return true;
}

// The minimum can rise while a channel mines steadily, such as the pool's for DATUM jobs, as
// SV1 checks on every job. A harder target goes out before the job that carries it.
static bool raise_to_min_diff(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_CHANNEL *ch, const T_DATUM_SV2_CTX *ctx, T_DATUM_SV2_SINK *out) {
	T_DATUM_SV2_SET_TARGET t = { .channel_id = ch->channel_id };
	uint64_t diff;

	if (ch->diff >= ctx->min_diff) return true;
	diff = fit_diff(ctx->min_diff, ch->max_target);
	if (diff <= ch->diff) return true; // max_target was checked when accepted
	ch->diff = diff;
	ch->snap_tsms = ctx->now_tsms;
	ch->shares_since_snap = 0;
	channel_target(diff, t.maximum_target);
	SEND(conn, out, DATUM_SV2_MSG_SET_TARGET, datum_sv2_encode_set_target, &t);
	return true;
}

bool datum_sv2_conn_send_work(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, bool new_prevhash, T_DATUM_SV2_SINK *out) {
	if (conn->state != DATUM_SV2_READY) return true;
	for (int i = 0; i < DATUM_SV2_MAX_CHANNELS; i++) {
		T_DATUM_SV2_CHANNEL *ch = &conn->channels[i];
		if (!ch->open) continue;
		if (!raise_to_min_diff(conn, ch, ctx, out) || !send_channel_job(conn, ch, ctx, new_prevhash, out)) return false;
	}
	return true;
}

static bool open_channel_error(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_SINK *out, uint32_t request_id, const char *code) {
	T_DATUM_SV2_OPEN_CHANNEL_ERROR e = { .request_id = request_id };
	datum_sv2_str_set(&e.error_code, code);
	SEND(conn, out, DATUM_SV2_MSG_OPEN_MINING_CHANNEL_ERROR, datum_sv2_encode_open_channel_error, &e);
	return true;
}

static bool handle_open_channel(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, bool extended, const unsigned char *pl, size_t len, T_DATUM_SV2_SINK *out) {
	T_DATUM_SV2_OPEN_CHANNEL m = {0}; // zeroed: the username's whole buffer is copied to the channel, which the dashboard reads unlocked
	T_DATUM_SV2_OPEN_CHANNEL_SUCCESS ok = { .extended = extended, .extranonce_size = DATUM_SV2_EXTRANONCE_SIZE };
	T_DATUM_SV2_CHANNEL *ch = NULL;
	int slot;

	if (!datum_sv2_decode_open_channel(pl, len, extended, &m)) return false;

	// a device that declared REQUIRES_STANDARD_JOBS cannot work extended jobs
	if (extended && (conn->setup_flags & DATUM_SV2_FLAG_REQUIRES_STANDARD_JOBS)) return open_channel_error(conn, out, m.request_id, "extended-channels-not-supported");
	if (extended && m.min_extranonce_size > DATUM_SV2_EXTRANONCE_SIZE) return open_channel_error(conn, out, m.request_id, "min-extranonce-size-too-large");
	if (!fit_diff(ctx->min_diff, m.max_target)) return open_channel_error(conn, out, m.request_id, "max-target-out-of-range");
	for (slot = 0; slot < DATUM_SV2_MAX_CHANNELS; slot++) {
		if (!conn->channels[slot].open) {
			ch = &conn->channels[slot];
			break;
		}
	}
	if (!ch) return open_channel_error(conn, out, m.request_id, "max-channels-reached");

	memset(ch, 0, sizeof(*ch));
	ch->open = true;
	ch->standard = !extended;
	ch->need_prevhash = true;
	ch->channel_id = conn->next_channel_id++;
	ch->session_id = channel_session_id(conn, slot);
	ch->user_identity = m.user_identity;
	ch->nominal_hash_rate = m.nominal_hash_rate;
	memcpy(ch->max_target, m.max_target, 32);
	ch->diff = fit_diff(datum_sv2_diff_for_hashrate(m.nominal_hash_rate, ctx->target_shares_min, ctx->min_diff), ch->max_target);
	ch->snap_tsms = ctx->now_tsms;
	ch->open_tsms = ctx->now_tsms;
	ch->stats.last_swap_tsms = ctx->now_tsms;

	ok.request_id = m.request_id;
	ok.channel_id = ch->channel_id;
	channel_target(ch->diff, ok.target);
	// extended channels get our 4 bytes and roll 8 of their own; a standard channel's whole extranonce is ours
	ok.extranonce_prefix.len = DATUM_SV2_EXTRANONCE_PREFIX_LEN;
	session_id_bytes(ch->session_id, ok.extranonce_prefix.b);
	if (ch->standard) {
		memcpy(&ok.extranonce_prefix.b[DATUM_SV2_EXTRANONCE_PREFIX_LEN], ch->extranonce, DATUM_SV2_EXTRANONCE_SIZE);
		ok.extranonce_prefix.len += DATUM_SV2_EXTRANONCE_SIZE;
	}
	ok.group_channel_id = 0;
	SEND(conn, out, extended ? DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS : DATUM_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, datum_sv2_encode_open_channel_success, &ok);

	// the first job on a new channel is a future job, activated by SetNewPrevHash
	return send_channel_job(conn, ch, ctx, true, out);
}

// Apply a new difficulty with SetTarget and a job whose coinbase carries it. SetTarget
// applies at once, but a job's coinbase is stamped with one difficulty, so the order
// keeps in-flight shares valid: raising, the harder target first (shares meeting it
// meet the older jobs too); lowering, the new job first.
static bool set_channel_diff(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_CHANNEL *ch, const T_DATUM_SV2_CTX *ctx, uint64_t diff, T_DATUM_SV2_SINK *out) {
	T_DATUM_SV2_SET_TARGET t = { .channel_id = ch->channel_id };
	bool lower;

	if (diff < ctx->min_diff) diff = ctx->min_diff;
	if (diff > DATUM_SV2_MAX_DIFF) diff = DATUM_SV2_MAX_DIFF;
	diff = fit_diff(diff, ch->max_target);
	if (!diff) return true; // max_target was checked when accepted
	ch->snap_tsms = ctx->now_tsms;
	ch->shares_since_snap = 0;
	if (diff == ch->diff) return true;
	lower = diff < ch->diff;
	ch->diff = diff;
	channel_target(diff, t.maximum_target);
	if (lower && !send_channel_job(conn, ch, ctx, false, out)) return false;
	SEND(conn, out, DATUM_SV2_MSG_SET_TARGET, datum_sv2_encode_set_target, &t);
	return lower ? true : send_channel_job(conn, ch, ctx, false, out);
}

static bool handle_update_channel(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, const unsigned char *pl, size_t len, T_DATUM_SV2_SINK *out) {
	T_DATUM_SV2_UPDATE_CHANNEL m;
	T_DATUM_SV2_CHANNEL *ch;
	unsigned char target[32];

	if (!datum_sv2_decode_update_channel(pl, len, &m)) return false;
	ch = find_channel(conn, m.channel_id);
	if (!ch || !fit_diff(ctx->min_diff, m.max_target)) {
		T_DATUM_SV2_CHANNEL_CODE e = { .channel_id = m.channel_id };
		datum_sv2_str_set(&e.code, ch ? "max-target-out-of-range" : "invalid-channel-id");
		SEND(conn, out, DATUM_SV2_MSG_UPDATE_CHANNEL_ERROR, datum_sv2_encode_channel_code, &e);
		return true;
	}
	ch->nominal_hash_rate = m.nominal_hash_rate;
	memcpy(ch->max_target, m.max_target, 32);
	// a new nominal hashrate retargets the channel, as on opening; without one, a max_target
	// below the current target must still be honoured with SetTarget
	if (m.nominal_hash_rate > 0) {
		return set_channel_diff(conn, ch, ctx, datum_sv2_diff_for_hashrate(m.nominal_hash_rate, ctx->target_shares_min, ctx->min_diff), out);
	}
	channel_target(ch->diff, target);
	if (compare_hashes(target, ch->max_target) > 0) return set_channel_diff(conn, ch, ctx, ch->diff, out);
	return true;
}

static bool handle_close_channel(T_DATUM_SV2_CONN *conn, const unsigned char *pl, size_t len) {
	T_DATUM_SV2_CHANNEL_CODE m;
	T_DATUM_SV2_CHANNEL *ch;

	if (!datum_sv2_decode_channel_code(pl, len, &m)) return false;
	ch = find_channel(conn, m.channel_id);
	if (ch) ch->open = false;
	return true;
}

// Vardiff, following the SV1 server's rules: aim for target_shares_min per minute,
// step a power of two at a time, and jump straight up when shares arrive far too fast.
static bool review_diff(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_CHANNEL *ch, const T_DATUM_SV2_CTX *ctx, T_DATUM_SV2_SINK *out) {
	uint64_t elapsed = ms_since(ctx->now_tsms, ch->snap_tsms);
	uint64_t target_ms = 60000 / (uint64_t)(ctx->target_shares_min > 0 ? ctx->target_shares_min : 1);
	uint64_t ms_per_share, diff;

	if (!ch->shares_since_snap) {
		if (elapsed > 60000) return set_channel_diff(conn, ch, ctx, ch->diff >> 1, out);
		return true;
	}
	if (elapsed < 1000) return true;
	ms_per_share = elapsed / ch->shares_since_snap;
	if (!ms_per_share) ms_per_share = 1;

	if (ctx->quickdiff_delta > 0 && ch->shares_since_snap >= (uint64_t)ctx->quickdiff_count && ms_per_share < target_ms / (uint64_t)ctx->quickdiff_delta) {
		diff = (target_ms / ms_per_share) * ch->diff;
		// cap it, including when the multiplication overflowed
		if (diff / ch->diff != target_ms / ms_per_share || diff > DATUM_SV2_MAX_DIFF) diff = DATUM_SV2_MAX_DIFF;
		diff = roundDownToPowerOfTwo_64(diff);
		if (diff < (ch->diff << 2)) diff = ch->diff << 2;
		return set_channel_diff(conn, ch, ctx, diff, out);
	}
	if (ms_per_share > target_ms * 2) return set_channel_diff(conn, ch, ctx, ch->diff >> 1, out);
	if (ch->shares_since_snap >= 16 && ms_per_share < target_ms / 2) return set_channel_diff(conn, ch, ctx, ch->diff << 1, out);
	return true;
}

bool datum_sv2_conn_tick(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, T_DATUM_SV2_SINK *out) {
	if (conn->state != DATUM_SV2_READY) return true;
	for (int i = 0; i < DATUM_SV2_MAX_CHANNELS; i++) {
		if (conn->channels[i].open && !review_diff(conn, &conn->channels[i], ctx, out)) return false;
	}
	return true;
}

const char *datum_sv2_conn_idle(const T_DATUM_SV2_CONN *conn, uint64_t now_tsms, int no_shares_s, int max_last_work_s) {
	if (conn->state != DATUM_SV2_READY) {
		return (ms_since(now_tsms, conn->connect_tsms) > DATUM_SV2_HANDSHAKE_TIMEOUT * 1000) ? "without completing setup" : NULL;
	}
	if (conn->shares_accepted) {
		if (max_last_work_s > 0 && ms_since(now_tsms, conn->last_share_tsms) > (uint64_t)max_last_work_s * 1000) return "since its last accepted share";
	} else if (no_shares_s > 0 && ms_since(now_tsms, conn->connect_tsms) > (uint64_t)no_shares_s * 1000) {
		return "without an accepted share";
	}
	return NULL;
}

static bool share_error(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_CHANNEL *ch, uint32_t channel_id, uint32_t sequence_number, const char *code, T_DATUM_SV2_SINK *out) {
	T_DATUM_SV2_SUBMIT_SHARES_ERROR e = { .channel_id = channel_id, .sequence_number = sequence_number };
	if (ch) {
		ch->shares_rejected++;
		ch->diff_rejected += ch->diff; // the share's own difficulty may be unknown, as in SV1
	}
	datum_stratum_count_share(false, ch ? ch->diff : 0);
	datum_sv2_str_set(&e.error_code, code);
	SEND(conn, out, DATUM_SV2_MSG_SUBMIT_SHARES_ERROR, datum_sv2_encode_submit_shares_error, &e);
	return true;
}

// The full coinbase and extranonce a share was mined on; false if the job's coinbase cannot hold it
static bool share_coinbase(const T_DATUM_SV2_CHANNEL *ch, const T_DATUM_SV2_JOB_REF *ref, const T_DATUM_STRATUM_JOB *job, const T_DATUM_SV2_SUBMIT_SHARES *m, unsigned char *full_cb_txn, size_t *cb_len, unsigned char extranonce_bin[12]) {
	const T_DATUM_STRATUM_COINBASE *cb = job_coinbase(job, ref->coinbase_index);
	
	// the coinbase holds 12 zero bytes where a SHA256d coinbase puts the extranonce, which here lives in the work root
	*cb_len = (size_t)cb->coinb1_len + 12 + (size_t)cb->coinb2_len;
	if (cb->coinb1_len <= job->target_pot_index || *cb_len > MAX_COINBASE_TXN_SIZE_BYTES) return false;
	channel_extranonce(ch, m->extranonce.b, extranonce_bin);
	memcpy(full_cb_txn, cb->coinb1_bin, cb->coinb1_len);
	memset(&full_cb_txn[cb->coinb1_len], 0, 12);
	memcpy(&full_cb_txn[cb->coinb1_len + 12], cb->coinb2_bin, cb->coinb2_len);
	full_cb_txn[job->target_pot_index] = floorPoT(ref->diff);
	return true;
}

bool datum_sv2_share_work(const T_DATUM_SV2_CHANNEL *ch, const T_DATUM_SV2_JOB_REF *ref, T_DATUM_STRATUM_JOB *job, const T_DATUM_SV2_SUBMIT_SHARES *m, unsigned char work[80], unsigned char *full_cb_txn, size_t *cb_len, unsigned char extranonce_bin[12]) {
	unsigned char nonce8[8], ntime8[8];
	
	if (!share_coinbase(ch, ref, job, m, full_cb_txn, cb_len, extranonce_bin)) return false;
	pk_u64le(nonce8, 0, m->nonce);
	pk_u64le(ntime8, 0, m->ntime);
	return datum_stratum_share_work(job, full_cb_txn, *cb_len, ref->coinbase_index == DATUM_COINBASE_ID_EMPTY, extranonce_bin, nonce8, ntime8, work);
}

static const char *share_result_code(T_DATUM_SHARE_RESULT r) {
	switch (r) {
		case DATUM_SHARE_H_NOT_ZERO:
		case DATUM_SHARE_HIGH_HASH: return "difficulty-too-low";
		case DATUM_SHARE_STALE_BLOCK:
		case DATUM_SHARE_STALE: return "stale-share";
		case DATUM_SHARE_TIME_TOO_OLD:
		case DATUM_SHARE_TIME_TOO_NEW: return "invalid-timestamp";
		case DATUM_SHARE_DUPLICATE: return "duplicate-share";
		default: return "invalid-share";
	}
}

// The job a share names, or why it cannot be accepted
static const char *share_job(T_DATUM_SV2_CHANNEL *ch, uint32_t job_id, T_DATUM_SV2_JOB_REF **ref_out, T_DATUM_STRATUM_JOB **job_out) {
	T_DATUM_SV2_JOB_REF *ref = NULL;
	T_DATUM_STRATUM_JOB *job;

	for (int i = 0; i < DATUM_SV2_JOB_REFS; i++) {
		if (ch->jobs[i].used && ch->jobs[i].job_id == job_id) {
			ref = &ch->jobs[i];
			break;
		}
	}
	if (!ref) return "invalid-job-id";
	job = global_cur_stratum_jobs[ref->global_index];
	if (!job || memcmp(job->job_id, ref->stratum_job_id, sizeof(ref->stratum_job_id))) return "invalid-job-id";
	*ref_out = ref;
	*job_out = job;
	return NULL;
}

// Run the checks the SV1 server uses on an assembled share and answer the miner
static bool finish_share(T_DATUM_SV2_CONN *conn, T_DATUM_SV2_CHANNEL *ch, const T_DATUM_SV2_JOB_REF *ref, const T_DATUM_SV2_CTX *ctx, const T_DATUM_SHARE *share, uint32_t sequence_number, T_DATUM_SV2_SINK *out) {
	T_DATUM_SHARE_OUTCOME outcome;
	const T_DATUM_SHARE_RESULT result = datum_stratum_check_share(share, &outcome);

	if (result != DATUM_SHARE_ACCEPTED) {
		return share_error(conn, ch, ch->channel_id, sequence_number, share_result_code(result), out);
	}
	datum_stratum_count_share(true, ref->diff);
	{
		T_DATUM_SV2_SUBMIT_SHARES_SUCCESS ok = { .channel_id = ch->channel_id, .last_sequence_number = sequence_number, .new_submits_accepted_count = 1, .new_shares_sum = ref->diff };
		SEND(conn, out, DATUM_SV2_MSG_SUBMIT_SHARES_SUCCESS, datum_sv2_encode_submit_shares_success, &ok);
	}
	ch->shares_accepted++;
	ch->diff_accepted += ref->diff;
	conn->shares_accepted++;
	conn->last_share_tsms = ctx->now_tsms;
	datum_stratum_stats_accepted(&ch->stats, ref->diff, ctx->now_tsms);
	ch->shares_since_snap++;
	return review_diff(conn, ch, ctx, out);
}

// Find the share's job, rebuild its work from the job's commitment and the share's nonce and time bytes, then run the checks the SV1 server uses.
static bool handle_submit_shares(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, bool extended, const unsigned char *pl, size_t len, T_DATUM_SV2_SINK *out) {
	T_DATUM_SV2_SUBMIT_SHARES m;
	T_DATUM_SV2_CHANNEL *ch;
	T_DATUM_SV2_JOB_REF *ref = NULL;
	T_DATUM_STRATUM_JOB *job = NULL;
	unsigned char extranonce_bin[DATUM_SV2_EXTRANONCE_PREFIX_LEN + DATUM_SV2_EXTRANONCE_SIZE];
	unsigned char full_cb_txn[MAX_COINBASE_TXN_SIZE_BYTES];
	unsigned char nonce8[8], ntime8[8], target[32];
	size_t cb_len;
	const char *err;
	
	if (!datum_sv2_decode_submit_shares(pl, len, extended, &m)) return false;
	ch = find_channel(conn, m.channel_id);
	if (!ch) return share_error(conn, NULL, m.channel_id, m.sequence_number, "invalid-channel-id", out);
	// each channel type has its own submit message
	const bool channel_extended = !ch->standard;
	if (extended != channel_extended) return share_error(conn, ch, m.channel_id, m.sequence_number, "invalid-channel-id", out);
	if (extended && m.extranonce.len != DATUM_SV2_EXTRANONCE_SIZE) return share_error(conn, ch, m.channel_id, m.sequence_number, "invalid-extranonce-size", out);
	if ((err = share_job(ch, m.job_id, &ref, &job))) return share_error(conn, ch, m.channel_id, m.sequence_number, err, out);
	if (!share_coinbase(ch, ref, job, &m, full_cb_txn, &cb_len, extranonce_bin)) return share_error(conn, ch, m.channel_id, m.sequence_number, "invalid-share", out);
	pk_u64le(nonce8, 0, m.nonce);
	pk_u64le(ntime8, 0, m.ntime);
	channel_target(ref->diff, target);

	const bool empty = ref->coinbase_index == DATUM_COINBASE_ID_EMPTY;
	const T_DATUM_SHARE share = {
		.c = ctx->client,
		.job = job,
		.sdata = ctx->sdata,
		.username = ch->user_identity.s,
		.username_len = ch->user_identity.len,
		.full_cb_txn = full_cb_txn,
		.full_cb_len = cb_len,
		.cb = job_coinbase(job, ref->coinbase_index),
		.extranonce_bin = extranonce_bin,
		.nonce8 = nonce8,
		.ntime8 = ntime8,
		.coinbase_index = ref->coinbase_index,
		.empty_work = empty,
		.quickdiff = false,
		.job_diff = ref->diff,
		.target = target,
		.stale_prevblock = ref->stale,
	};
	return finish_share(conn, ch, ref, ctx, &share, m.sequence_number, out);
}

static bool handle_message(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, const unsigned char *pl, size_t len, T_DATUM_SV2_SINK *out) {
	const T_DATUM_SV2_FRAME_HEADER *h = &conn->header;

	// extension messages are not for us
	if (h->extension_type != 0) return true;

	if (conn->state == DATUM_SV2_AWAIT_SETUP) {
		if (h->msg_type != DATUM_SV2_MSG_SETUP_CONNECTION) return false;
		return handle_setup_connection(conn, pl, len, out);
	}

	switch (h->msg_type) {
		case DATUM_SV2_MSG_OPEN_STANDARD_MINING_CHANNEL: return handle_open_channel(conn, ctx, false, pl, len, out);
		case DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL: return handle_open_channel(conn, ctx, true, pl, len, out);
		case DATUM_SV2_MSG_UPDATE_CHANNEL: return handle_update_channel(conn, ctx, pl, len, out);
		case DATUM_SV2_MSG_CLOSE_CHANNEL: return handle_close_channel(conn, pl, len);
		case DATUM_SV2_MSG_SUBMIT_SHARES_STANDARD: return handle_submit_shares(conn, ctx, false, pl, len, out);
		case DATUM_SV2_MSG_SUBMIT_SHARES_EXTENDED: return handle_submit_shares(conn, ctx, true, pl, len, out);
		case DATUM_SV2_MSG_SETUP_CONNECTION: return false; // only once per connection
		default: return true; // ignore what we do not serve
	}
}

bool datum_sv2_conn_feed(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, const unsigned char *in, size_t in_len, size_t *consumed, T_DATUM_SV2_SINK *out) {
	unsigned char header[DATUM_SV2_FRAME_HEADER_LEN];
	unsigned char payload[DATUM_SV2_MAX_IN_PAYLOAD];
	size_t pos = 0, ct_len;
	bool ok = true;

	while (ok) {
		if (conn->state == DATUM_SV2_AWAIT_HANDSHAKE) {
			if (in_len - pos < DATUM_SV2_NOISE_ACT1_LEN) break;
			if (out->cap - out->len < DATUM_SV2_NOISE_ACT2_LEN) { ok = false; break; }
			if (!datum_sv2_noise_respond(ctx->id, &in[pos], &out->buf[out->len], &conn->noise, ctx->now)) { ok = false; break; }
			out->len += DATUM_SV2_NOISE_ACT2_LEN;
			pos += DATUM_SV2_NOISE_ACT1_LEN;
			conn->state = DATUM_SV2_AWAIT_SETUP;
			continue;
		}

		if (!conn->have_header) {
			if (in_len - pos < DATUM_SV2_NOISE_HEADER_CT_LEN) break;
			if (!datum_sv2_noise_decrypt_header(&conn->noise.decrypt, &in[pos], header)) { ok = false; break; }
			pos += DATUM_SV2_NOISE_HEADER_CT_LEN;
			datum_sv2_header_decode(header, &conn->header);
			if (conn->header.length > DATUM_SV2_MAX_IN_PAYLOAD) { ok = false; break; }
			conn->have_header = true;
		}

		ct_len = datum_sv2_noise_payload_ct_len(conn->header.length);
		if (in_len - pos < ct_len) break;
		if (!datum_sv2_noise_decrypt_payload(&conn->noise.decrypt, &in[pos], conn->header.length, payload)) { ok = false; break; }
		pos += ct_len;
		conn->have_header = false;
		ok = handle_message(conn, ctx, payload, conn->header.length, out);
	}

	sodium_memzero(payload, sizeof(payload));
	*consumed = pos;
	return ok;
}

bool datum_sv2_authority_pubkey_b58(const unsigned char pk_xonly[32], char *out, size_t out_len) {
	// SV2 keys start with version 1 as two little-endian bytes, [1, 0]: b58check_enc
	// writes the first as its version byte and data[0] holds the second
	unsigned char data[33];
	data[0] = 0;
	memcpy(&data[1], pk_xonly, 32);
	return b58check_enc(out, &out_len, 1, data, sizeof(data));
}

// --- socket app ---

typedef struct {
	T_DATUM_STRATUM_THREADPOOL_DATA sdata; // dupe checker, coinbaser readiness, block submission buffer
	T_DATUM_SV2_WORK work;
	int latest_job_index;
	bool work_pending;
	uint64_t next_tick_tsms;
} T_DATUM_SV2_THREAD;

static T_DATUM_SV2_NOISE_IDENTITY sv2_identity;
static T_DATUM_SOCKET_APP *sv2_app = NULL;

static void datum_sv2_fill_ctx(T_DATUM_SV2_CTX *ctx, T_DATUM_SV2_THREAD *t, const T_DATUM_CLIENT_DATA *c) {
	// the SV1 vardiff settings, including the pool's minimum for DATUM jobs
	const uint64_t min_diff = datum_sv2_min_diff((uint64_t)datum_config.stratum_v1_vardiff_min, (uint64_t)datum_config.override_vardiff_min, t->work.job && t->work.job->is_datum_job);
	memset(ctx, 0, sizeof(*ctx));
	ctx->id = &sv2_identity;
	ctx->now = (uint32_t)time(NULL);
	ctx->now_tsms = current_time_millis();
	ctx->min_diff = min_diff;
	ctx->target_shares_min = datum_config.stratum_v1_vardiff_target_shares_min;
	ctx->quickdiff_count = datum_config.stratum_v1_vardiff_quickdiff_count;
	ctx->quickdiff_delta = datum_config.stratum_v1_vardiff_quickdiff_delta;
	ctx->work = &t->work;
	ctx->sdata = &t->sdata;
	ctx->client = c;
}

static T_DATUM_SV2_SINK client_sink(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_SV2_SINK out = { .buf = (unsigned char *)&c->w_buffer[c->out_buf], .cap = (size_t)(CLIENT_BUFFER - 1 - c->out_buf), .len = 0 };
	return out;
}

static void datum_sv2_thread_init(T_DATUM_THREAD_DATA *my) {
	T_DATUM_SV2_THREAD *t = my->app_thread_data;
	t->latest_job_index = -1;
	datum_stratum_dupes_init(&t->sdata);
}

static void datum_sv2_client_new(T_DATUM_CLIENT_DATA *c) {
	c->kill_request = false; // a kill aimed at this slot's previous client
	datum_sv2_conn_init(c->app_client_data, datum_sv2_session_base(c->datum_thread->thread_id, c->cid), current_time_millis());
}

static void datum_sv2_client_closed(T_DATUM_CLIENT_DATA *c, const char *msg) {
	T_DATUM_SV2_CONN *conn = c->app_client_data;
	DLOG_DEBUG("Stratum V2 client %d/%d (%s) closed: %s", c->datum_thread->thread_id, c->cid, c->rem_host, msg);
	datum_sv2_conn_wipe(conn);
}

static int datum_sv2_client_data(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_SV2_CONN *conn = c->app_client_data;
	T_DATUM_SV2_CTX ctx;
	T_DATUM_SV2_SINK out = client_sink(c);
	size_t consumed = 0;
	bool ok;

	datum_sv2_fill_ctx(&ctx, c->datum_thread->app_thread_data, c);
	ok = datum_sv2_conn_feed(conn, &ctx, (const unsigned char *)c->buffer, (size_t)c->in_buf, &consumed, &out);
	c->out_buf += (int)out.len;
	if (consumed) {
		memmove(c->buffer, &c->buffer[consumed], (size_t)c->in_buf - consumed);
		c->in_buf -= (int)consumed;
	}
	if (!ok) {
		// best effort to deliver a queued error message before closing
		if (c->out_buf > 0) {
			ssize_t ignored = send(c->fd, c->w_buffer, c->out_buf, MSG_DONTWAIT);
			(void)ignored;
		}
		return -1;
	}
	return 0;
}

static void datum_sv2_kill(T_DATUM_THREAD_DATA *my, T_DATUM_CLIENT_DATA *c) {
	c->kill_request = true;
	my->has_client_kill_request = true;
}

// Pick up new stratum work. Returns true when channels need it, with *new_prevhash set for a new block.
static bool datum_sv2_update_work(T_DATUM_SV2_THREAD *t, bool *new_prevhash) {
	T_DATUM_STRATUM_JOB *job = NULL;
	int idx;

	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	idx = global_latest_stratum_job_index;
	if (idx >= 0) job = global_cur_stratum_jobs[idx];
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);

	if (job && idx != t->latest_job_index) {
		t->latest_job_index = idx;
		t->work_pending = true;
		t->sdata.full_coinbase_ready = false;
	}
	if (!t->work_pending || !job) return false;

	*new_prevhash = !t->work.job || memcmp(job->prevhash_bin, t->work.prevhash, 32) != 0;

	// a new block starts with subsidy-only work so hashing resumes right away
	if (*new_prevhash && (job->job_state == JOB_STATE_EMPTY_ONLY || job->job_state == JOB_STATE_EMPTY_PLUS)) {
		t->work.job = job;
		t->work.subsidy_only = true;
		t->work.full_coinbase = false;
		memcpy(t->work.prevhash, job->prevhash_bin, 32);
		// an EMPTY_PLUS job's full work follows on the next loop
		t->work_pending = job->job_state == JOB_STATE_EMPTY_PLUS;
		return true;
	}
	if (job->job_state == JOB_STATE_UNKNOWN || job->job_state == JOB_STATE_EMPTY_ONLY) {
		t->work_pending = false;
		return false;
	}
	if (job->job_state >= JOB_STATE_FULL_PRIORITY_WAIT_COINBASER && !stratum_job_coinbaser_ready(&t->sdata, job)) {
		return false; // wait for the pool's coinbase outputs (times out after 5 s)
	}

	t->work.job = job;
	t->work.subsidy_only = false;
	t->work.full_coinbase = job->job_state >= JOB_STATE_FULL_PRIORITY_WAIT_COINBASER && t->sdata.full_coinbase_ready;
	memcpy(t->work.prevhash, job->prevhash_bin, 32);
	t->work_pending = false;
	return true;
}

static void datum_sv2_thread_loop(T_DATUM_THREAD_DATA *my) {
	T_DATUM_SV2_THREAD *t = my->app_thread_data;
	uint64_t now = current_time_millis();
	bool new_prevhash = false, have_work, tick;

	t->sdata.loop_tsms = now;
	have_work = datum_sv2_update_work(t, &new_prevhash);
	tick = now >= t->next_tick_tsms;
	if (tick) t->next_tick_tsms = now + 5000;

	for (int i = 0; i < my->app->max_clients_thread; i++) {
		T_DATUM_CLIENT_DATA *c = &my->client_data[i];
		T_DATUM_SV2_CONN *conn = c->app_client_data;
		T_DATUM_SV2_CTX ctx;
		T_DATUM_SV2_SINK out;
		bool ok = true;

		if (c->fd <= 0 || c->kill_request) continue;
		if (tick || conn->state != DATUM_SV2_READY) {
			const char *why = datum_sv2_conn_idle(conn, now, datum_config.stratum_v1_idle_timeout_no_share, datum_config.stratum_v1_idle_timeout_max_last_work);
			if (why) {
				DLOG_DEBUG("Kicking Stratum V2 client %d/%d (%s) for being idle %s", my->thread_id, i, c->rem_host, why);
				datum_sv2_kill(my, c);
				continue;
			}
		}
		if (conn->state != DATUM_SV2_READY) continue;
		if (!have_work && !tick) continue;

		datum_sv2_fill_ctx(&ctx, t, c);
		out = client_sink(c);
		if (have_work) ok = datum_sv2_conn_send_work(conn, &ctx, new_prevhash, &out);
		if (ok && tick) ok = datum_sv2_conn_tick(conn, &ctx, &out);
		c->out_buf += (int)out.len;
		if (!ok) {
			// the client is not draining its send buffer
			DLOG_DEBUG("Stratum V2 client %d/%d (%s) send buffer full; disconnecting", my->thread_id, i, c->rem_host);
			datum_sv2_kill(my, c);
		}
	}
}

static bool parse_hex32(const char *hex, unsigned char out[32]) {
	if (strlen(hex) != 64) return false;
	for (int i = 0; i < 64; i++) {
		char ch = hex[i];
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false;
	}
	for (int i = 0; i < 32; i++) out[i] = hex2bin_uchar(&hex[2 * i]);
	return true;
}

bool datum_sv2_authority_key_valid(const char *hex) {
	T_DATUM_SV2_NOISE_IDENTITY id;
	unsigned char sk[32];
	bool ok = parse_hex32(hex, sk) && datum_sv2_noise_identity_init(&id, sk, 60);
	sodium_memzero(sk, sizeof(sk));
	sodium_memzero(&id, sizeof(id));
	return ok;
}

// Started as its own pthread during startup when stratum_v2.listen_port is set
void *datum_sv2_socket_server(void *arg) {
	T_DATUM_SOCKET_APP *app;
	T_DATUM_SV2_CONN *conns;
	T_DATUM_SV2_THREAD *threads;
	pthread_t pthread_listener;
	unsigned char authority_sk[32];
	char authority_b58[128];
	int ret;

	(void)arg;

	if (!parse_hex32(datum_config.stratum_v2_authority_secret_key, authority_sk) ||
	    !datum_sv2_noise_identity_init(&sv2_identity, authority_sk, (uint32_t)datum_config.stratum_v2_cert_validity)) {
		sodium_memzero(authority_sk, sizeof(authority_sk));
		DLOG_FATAL("stratum_v2.authority_secret_key is not a valid secp256k1 secret key.");
		panic_from_thread(__LINE__);
		return NULL;
	}
	sodium_memzero(authority_sk, sizeof(authority_sk));
	if (datum_sv2_authority_pubkey_b58(sv2_identity.authority_pk_xonly, authority_b58, sizeof(authority_b58))) {
		DLOG_INFO("Stratum V2 authority public key (configure this on miners): %s", authority_b58);
	}

	app = calloc(1, sizeof(T_DATUM_SOCKET_APP));
	if (!app) {
		DLOG_FATAL("Could not allocate memory for Stratum V2 server app metadata!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	strcpy(app->name, "Stratum V2 Server");
	app->init_func = datum_sv2_thread_init;
	app->loop_func = datum_sv2_thread_loop;
	app->client_data_func = datum_sv2_client_data;
	app->closed_client_func = datum_sv2_client_closed;
	app->new_client_func = datum_sv2_client_new;
	app->listen_addr = datum_config.stratum_v2_listen_addr;
	app->listen_port = datum_config.stratum_v2_listen_port;
	// Fixed limits, unlike SV1's configurable ones: 256 connections, each with up to
	// DATUM_SV2_MAX_CHANNELS channels, is far more than SV2 devices need today
	app->max_threads = 2;
	app->max_clients_thread = 128;
	app->max_clients = app->max_threads * app->max_clients_thread;

	app->datum_threads = calloc(app->max_threads + 1, sizeof(T_DATUM_THREAD_DATA));
	threads = calloc(app->max_threads, sizeof(T_DATUM_SV2_THREAD));
	conns = calloc((size_t)app->max_threads * app->max_clients_thread, sizeof(T_DATUM_SV2_CONN));
	if (!app->datum_threads || !threads || !conns) {
		DLOG_FATAL("Could not allocate memory for Stratum V2 server thread data!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	for (int t = 0; t < app->max_threads; t++) {
		app->datum_threads[t].app_thread_data = &threads[t];
		for (int i = 0; i < app->max_clients_thread; i++) {
			app->datum_threads[t].client_data[i].app_client_data = &conns[t * app->max_clients_thread + i];
		}
	}

	sv2_app = app;
	ret = datum_thread_create(&pthread_listener, datum_gateway_listener_thread, app);
	if (ret != 0) {
		DLOG_FATAL("Could not pthread_create for Stratum V2 listener!: %s", strerror(ret));
		panic_from_thread(__LINE__);
		return NULL;
	}
	DLOG_INFO("Stratum V2 Server Init complete.");
	return NULL;
}

// --- dashboard, API and pool-loss hooks (read like the SV1 server's: without locks, best effort) ---

void datum_sv2_foreach_channel(void (*fn)(const T_DATUM_SV2_CHANNEL_VIEW *v, void *arg), void *arg) {
	if (!sv2_app) return;
	for (int t = 0; t < sv2_app->max_threads; t++) {
		const T_DATUM_SV2_THREAD *th = sv2_app->datum_threads[t].app_thread_data;
		for (int i = 0; i < sv2_app->max_clients_thread; i++) {
			const T_DATUM_CLIENT_DATA *c = &sv2_app->datum_threads[t].client_data[i];
			const T_DATUM_SV2_CONN *conn = c->app_client_data;
			if (c->fd <= 0) continue;
			for (int k = 0; k < DATUM_SV2_MAX_CHANNELS; k++) {
				T_DATUM_SV2_CHANNEL_VIEW v;
				if (!conn->channels[k].open) continue;
				v.tid = t;
				v.cid = i;
				v.rem_host = c->rem_host;
				v.conn = conn;
				v.channel = &conn->channels[k];
				v.coinbase_index = th->work.job ? work_coinbase_index(&th->work) : 0;
				fn(&v, arg);
			}
		}
	}
}

static void summary_add(const T_DATUM_SV2_CHANNEL_VIEW *v, void *arg) {
	T_DATUM_SV2_SUMMARY *s = arg;
	s->channels++;
	// count only estimates refreshed in the last three minutes, as SV1 does
	if (ms_since(current_time_millis(), v->channel->stats.last_swap_tsms) < 180000) s->th_sec += datum_stratum_stats_th_sec(&v->channel->stats);
}

void datum_sv2_summary(T_DATUM_SV2_SUMMARY *s) {
	memset(s, 0, sizeof(*s));
	if (!sv2_app) return;
	for (int t = 0; t < sv2_app->max_threads; t++) s->connections += sv2_app->datum_threads[t].connected_clients;
	datum_sv2_foreach_channel(summary_add, s);
}

bool datum_sv2_kill_client(int tid, int cid, uint64_t connect_tsms) {
	const T_DATUM_SV2_CONN *conn;
	if (!sv2_app || tid < 0 || tid >= sv2_app->max_threads || cid < 0 || cid >= sv2_app->max_clients_thread) return false;
	if (sv2_app->datum_threads[tid].client_data[cid].fd <= 0) return false;
	conn = sv2_app->datum_threads[tid].client_data[cid].app_client_data;
	if (conn->connect_tsms != connect_tsms) {
		DLOG_WARN("API Request to disconnect FORMER Stratum V2 client %d/%d (ignored; connect tsms req=%lu vs cur=%lu)", tid, cid, (unsigned long)connect_tsms, (unsigned long)conn->connect_tsms);
		return false;
	}
	DLOG_WARN("API Request to disconnect Stratum V2 client %d/%d!", tid, cid);
	datum_sv2_kill(&sv2_app->datum_threads[tid], &sv2_app->datum_threads[tid].client_data[cid]);
	return true;
}

void datum_sv2_shutdown_all(void) {
	unsigned int n = 0;
	if (!sv2_app) return;
	for (int t = 0; t < sv2_app->max_threads; t++) {
		if (!sv2_app->datum_threads[t].is_active) continue;
		pthread_mutex_lock(&sv2_app->datum_threads[t].thread_data_lock);
		sv2_app->datum_threads[t].empty_request = true;
		pthread_mutex_unlock(&sv2_app->datum_threads[t].thread_data_lock);
		n++;
	}
	DLOG_INFO("Sent disconnect request for all Stratum V2 clients to %u threads.", n);
}
