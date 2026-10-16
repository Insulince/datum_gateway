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

// Stratum V2 server: one connection's protocol state (Noise handshake,
// SetupConnection, mining channels, jobs and shares) and the socket app that
// hosts it.
//
// Work is served on standard and extended channels. Each channel's coinbase
// extranonce is a 4-byte session ID drawn from a range the Stratum V1 server
// never assigns, followed by 8 more bytes: the miner's on an extended channel,
// ours on a standard one. That is SV1's 4 + 8 coinbase layout, so shares travel
// the same validation and DATUM submission path.
//
// The work is BLAKE2b, carried by the core job, SetNewPrevHash and share messages
// with the layouts in doc/sv2_xbt.md.

#ifndef _DATUM_SV2_H_
#define _DATUM_SV2_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "datum_sockets.h"
#include "datum_stratum.h"
#include "datum_sv2_msg.h"
#include "datum_sv2_noise.h"

#define DATUM_SV2_MAX_CHANNELS 16
#define DATUM_SV2_EXTRANONCE_PREFIX_LEN 4
#define DATUM_SV2_EXTRANONCE_SIZE 8
#define DATUM_SV2_MAX_IN_PAYLOAD 4096 // everything a client sends is far smaller
#define DATUM_SV2_HANDSHAKE_TIMEOUT 30 // seconds to complete the handshake and SetupConnection
#define DATUM_SV2_JOB_REFS 32 // jobs per channel a share may still reference; covers SV1's stale window at its fastest job cadence

// Coinbase layout once the pool's outputs are in. An SV2 device never sees the coinbase (a
// standard channel gets the merkle root, an extended one the commitment), so every channel
// gets the largest, which fits the most pool payouts.
#define DATUM_SV2_COINBASE 4

typedef enum {
	DATUM_SV2_AWAIT_HANDSHAKE = 0,
	DATUM_SV2_AWAIT_SETUP,
	DATUM_SV2_READY,
} T_DATUM_SV2_CONN_STATE;

// A job sent on a channel, enough to rebuild the coinbase a share was mined on.
typedef struct {
	bool used;
	bool stale; // superseded by a new prev_hash: still recognised, no longer accepted
	uint32_t job_id;
	uint16_t global_index; // into global_cur_stratum_jobs
	char stratum_job_id[24]; // the stratum job's id, which detects a recycled slot
	uint8_t coinbase_index; // DATUM_COINBASE_ID_EMPTY for new-block subsidy-only work
	uint64_t diff;          // power of two, stamped into the coinbase
} T_DATUM_SV2_JOB_REF;

typedef struct {
	bool open;
	bool standard; // header-only mining: we send the merkle root, the device rolls no extranonce
	bool need_prevhash; // the next job is announced with SetNewPrevHash (new channel, or work resumes)
	uint32_t channel_id;
	uint32_t session_id; // first 4 extranonce bytes, big-endian like SV1's extranonce1
	unsigned char extranonce[DATUM_SV2_EXTRANONCE_SIZE]; // standard channels: the rest of the extranonce, all zero (the session ID before it is already unique)
	T_DATUM_SV2_STR user_identity;
	float nominal_hash_rate;
	unsigned char max_target[32];

	uint64_t diff; // current power-of-two difficulty
	T_DATUM_SV2_JOB_REF jobs[DATUM_SV2_JOB_REFS];
	unsigned int next_job_ref;

	// vardiff
	uint64_t snap_tsms;
	uint64_t shares_since_snap;

	uint64_t shares_accepted;
	uint64_t diff_accepted;
	uint64_t shares_rejected;
	uint64_t diff_rejected;
	uint64_t open_tsms;
	T_DATUM_STRATUM_USER_STATS stats; // for the hashrate estimate, as SV1 keeps per miner
} T_DATUM_SV2_CHANNEL;

typedef struct {
	T_DATUM_SV2_CONN_STATE state;
	T_DATUM_SV2_NOISE_SESSION noise;
	uint64_t connect_tsms;

	// pending decrypted frame header
	bool have_header;
	T_DATUM_SV2_FRAME_HEADER header;

	uint32_t setup_flags;
	char vendor[64];
	char firmware[64];

	uint32_t session_base; // upper bits of every channel session ID on this connection
	uint32_t next_channel_id;
	uint32_t next_job_id;
	T_DATUM_SV2_CHANNEL channels[DATUM_SV2_MAX_CHANNELS];

	// across every channel, for the idle timeouts
	uint64_t shares_accepted;
	uint64_t last_share_tsms;
} T_DATUM_SV2_CONN;

// The work every channel on a thread is being served.
typedef struct {
	T_DATUM_STRATUM_JOB *job; // NULL until the first job exists
	bool subsidy_only;        // empty work for a new block
	bool full_coinbase;       // the pool's coinbase outputs are in
	unsigned char prevhash[32]; // the job's prev_hash, to spot a new block
} T_DATUM_SV2_WORK;

// Bytes to send, appended by the protocol code.
typedef struct {
	unsigned char *buf;
	size_t cap;
	size_t len;
} T_DATUM_SV2_SINK;

typedef struct {
	const T_DATUM_SV2_NOISE_IDENTITY *id;
	uint32_t now;      // unix seconds, for certificates
	uint64_t now_tsms; // wall-clock milliseconds, as the SV1 server uses
	uint64_t min_diff; // power of two
	int target_shares_min; // vardiff aim, shares per minute
	int quickdiff_count;   // shares seen before a quick jump is considered
	int quickdiff_delta;   // how many times too fast triggers a quick jump
	const T_DATUM_SV2_WORK *work;
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata; // dupe checker and block submission buffer
	const T_DATUM_CLIENT_DATA *client;      // passed through to DATUM share submission
} T_DATUM_SV2_CTX;

void datum_sv2_conn_init(T_DATUM_SV2_CONN *conn, uint32_t session_base, uint64_t now_tsms);
void datum_sv2_conn_wipe(T_DATUM_SV2_CONN *conn);

// Feed received bytes. Consumes whole messages only; *consumed says how many
// bytes to drop from the front of in. Returns false when the connection must
// be closed (after sending anything left in out).
bool datum_sv2_conn_feed(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, const unsigned char *in, size_t in_len, size_t *consumed, T_DATUM_SV2_SINK *out);

// Send ctx->work to every open channel: a future job plus SetNewPrevHash when
// the prev_hash changed, otherwise a job to mine immediately.
bool datum_sv2_conn_send_work(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, bool new_prevhash, T_DATUM_SV2_SINK *out);

// The 80-byte work and full coinbase a share describes (exposed for tests); false if the job's commitment cannot be built.
bool datum_sv2_share_work(const T_DATUM_SV2_CHANNEL *ch, const T_DATUM_SV2_JOB_REF *ref, T_DATUM_STRATUM_JOB *job, const T_DATUM_SV2_SUBMIT_SHARES *m, unsigned char work[80], unsigned char *full_cb_txn, size_t *cb_len, unsigned char extranonce_bin[12]);

// Periodic difficulty review for channels that have gone quiet.
bool datum_sv2_conn_tick(T_DATUM_SV2_CONN *conn, const T_DATUM_SV2_CTX *ctx, T_DATUM_SV2_SINK *out);

// Why an idle connection should be dropped, judged like the SV1 server's idle_timeout_*
// settings (seconds, 0 disables); NULL to keep it. A connection that is set up counts
// as subscribed: a proxy may hold no channel until a miner arrives behind it.
const char *datum_sv2_conn_idle(const T_DATUM_SV2_CONN *conn, uint64_t now_tsms, int no_shares_s, int max_last_work_s);

// Session IDs (the first 4 extranonce bytes) must never collide with SV1's. SV1 uses
// ((thread << 22) | client) ^ 0xB10CF00D with thread < 64, so bit 31 is always clear
// before the XOR. SV2 uses the same XOR over this layout, with bit 31 set:
//   bit 31: 1 | bits 30-22: thread | bits 21-10: client | bits 9-0: channel slot
uint32_t datum_sv2_session_base(int thread_id, int client_id);

// Difficulty that yields roughly target_shares_min shares/minute at hash_rate, as a power of two >= min_diff.
uint64_t datum_sv2_diff_for_hashrate(float hash_rate, int target_shares_min, uint64_t min_diff);
// The lowest share difficulty: SV1's floor, raised on DATUM jobs to the pool's minimum,
// as a power of two that is never below either
uint64_t datum_sv2_min_diff(uint64_t v1_min, uint64_t pool_min, bool datum_job);
// Whether a configured authority secret key is 64 hex characters naming a valid secp256k1 key
bool datum_sv2_authority_key_valid(const char *hex);

// Authority public key in the SV2 base58check form miners configure.
bool datum_sv2_authority_pubkey_b58(const unsigned char pk_xonly[32], char *out, size_t out_len);

// For the dashboard, API and stats log
typedef struct {
	int connections;
	int channels;
	double th_sec;
} T_DATUM_SV2_SUMMARY;

typedef struct {
	int tid;
	int cid;
	const char *rem_host;
	const T_DATUM_SV2_CONN *conn;
	const T_DATUM_SV2_CHANNEL *channel;
	uint8_t coinbase_index; // what new jobs on this channel use
} T_DATUM_SV2_CHANNEL_VIEW;

// The gateway calls these whether or not SV2 is built; without it they do nothing.
#ifdef ENABLE_SV2
void *datum_sv2_socket_server(void *arg);
void datum_sv2_summary(T_DATUM_SV2_SUMMARY *s);
void datum_sv2_foreach_channel(void (*fn)(const T_DATUM_SV2_CHANNEL_VIEW *v, void *arg), void *arg);
// connect_tsms must match the connection's, so a reused slot is not kicked by mistake
bool datum_sv2_kill_client(int tid, int cid, uint64_t connect_tsms);
// Disconnect every SV2 miner, as the SV1 server does when pooled-only mining loses its pool
void datum_sv2_shutdown_all(void);
#else
static inline void *datum_sv2_socket_server(void *arg) { (void)arg; return NULL; }
static inline void datum_sv2_summary(T_DATUM_SV2_SUMMARY *s) { *s = (T_DATUM_SV2_SUMMARY){0}; }
static inline void datum_sv2_foreach_channel(void (*fn)(const T_DATUM_SV2_CHANNEL_VIEW *v, void *arg), void *arg) { (void)fn; (void)arg; }
static inline bool datum_sv2_kill_client(int tid, int cid, uint64_t connect_tsms) { (void)tid; (void)cid; (void)connect_tsms; return false; }
static inline void datum_sv2_shutdown_all(void) {}
#endif

#endif
