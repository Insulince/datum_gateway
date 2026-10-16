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
#include <string.h>

#include "datum_sv2_msg.h"
#include "datum_utils.h"

// Every expected payload below was serialized by the SRI crates binary_sv2 7.0.0,
// common_messages_sv2 9.0.0 and mining_sv2 12.0.0 from the same field values. The
// messages that carry work (jobs, SetNewPrevHash, shares) were serialized by
// binary_sv2 from structs declaring doc/sv2_xbt.md's fields, so they check field
// order and SV2 type encodings, not just round trips.

static size_t unhex(const char *s, unsigned char *out, size_t cap) {
	size_t n = strlen(s) / 2;
	if (n > cap) return 0;
	for (size_t i = 0; i < n; i++) out[i] = hex2bin_uchar(&s[2 * i]);
	return n;
}

static bool same(const unsigned char *got, size_t got_len, const char *hex) {
	unsigned char want[512];
	size_t n = unhex(hex, want, sizeof(want));
	return n && got_len == n && 0 == memcmp(got, want, n);
}

static unsigned char target[32], max_target[32], root[32], prev[32];

static void init_values(void) {
	for (int i = 0; i < 32; i++) {
		target[i] = (unsigned char)i;
		max_target[i] = 0xff;
		root[i] = (unsigned char)(i * 3);
		prev[i] = (unsigned char)(255 - i);
	}
}

static const char hex_setup_connection[] = "0002000200040000000831302e302e302e35265b074269746d61696e035332310f62726169696e732d6f732d32303236056465762d31";
static const char hex_open_standard[] = "070000001062633171746573742e776f726b65723121e6b556ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char hex_open_extended[] = "070000001062633171746573742e776f726b65723121e6b556ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0800";
static const char hex_update_channel[] = "0400000021e6b555ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char hex_close_channel[] = "040000000873687574646f776e";
static const char hex_submit_standard[] = "03000000090000000b000000efcdab89674523010078e76805000000";
static const char hex_submit_extended[] = "04000000090000000b000000efcdab89674523010078e7680000000008a0a1a2a3a4a5a6a7";

// messages the server receives: decode SRI bytes
static void datum_sv2_msg_tests_decode(void) {
	unsigned char buf[256];
	size_t n;
	T_DATUM_SV2_SETUP_CONNECTION sc;
	T_DATUM_SV2_OPEN_CHANNEL oc;
	T_DATUM_SV2_UPDATE_CHANNEL uc;
	T_DATUM_SV2_CHANNEL_CODE cc;
	T_DATUM_SV2_SUBMIT_SHARES ss;

	n = unhex(hex_setup_connection, buf, sizeof(buf));
	datum_test(datum_sv2_decode_setup_connection(buf, n, &sc));
	datum_test(sc.protocol == DATUM_SV2_PROTOCOL_MINING && sc.min_version == 2 && sc.max_version == 2);
	datum_test(sc.flags == DATUM_SV2_FLAG_REQUIRES_VERSION_ROLLING);
	datum_test(0 == strcmp(sc.endpoint_host.s, "10.0.0.5") && sc.endpoint_port == 23334);
	datum_test(0 == strcmp(sc.vendor.s, "Bitmain") && 0 == strcmp(sc.hardware_version.s, "S21"));
	datum_test(0 == strcmp(sc.firmware.s, "braiins-os-2026") && 0 == strcmp(sc.device_id.s, "dev-1"));
	datum_test(!datum_sv2_decode_setup_connection(buf, n - 1, &sc)); // truncated
	buf[n] = 0;
	datum_test(!datum_sv2_decode_setup_connection(buf, n + 1, &sc)); // trailing byte

	n = unhex(hex_open_standard, buf, sizeof(buf));
	datum_test(datum_sv2_decode_open_channel(buf, n, false, &oc));
	datum_test(oc.request_id == 7 && 0 == strcmp(oc.user_identity.s, "bc1qtest.worker1"));
	datum_test(oc.nominal_hash_rate == 1.0e14f && 0 == memcmp(oc.max_target, max_target, 32));
	datum_test(!datum_sv2_decode_open_channel(buf, n, true, &oc)); // too short for extended

	n = unhex(hex_open_extended, buf, sizeof(buf));
	datum_test(datum_sv2_decode_open_channel(buf, n, true, &oc));
	datum_test(oc.extended && oc.request_id == 7 && oc.min_extranonce_size == 8);

	// F32 rules: negative, -0.0 and NaN are protocol errors (hashrate starts at byte 21)
	n = unhex(hex_open_standard, buf, sizeof(buf));
	buf[24] |= 0x80;
	datum_test(!datum_sv2_decode_open_channel(buf, n, false, &oc));
	memset(&buf[21], 0, 4);
	buf[24] = 0x80;
	datum_test(!datum_sv2_decode_open_channel(buf, n, false, &oc));
	buf[21] = 1; buf[22] = 0; buf[23] = 0xc0; buf[24] = 0x7f;
	datum_test(!datum_sv2_decode_open_channel(buf, n, false, &oc));

	n = unhex(hex_update_channel, buf, sizeof(buf));
	datum_test(datum_sv2_decode_update_channel(buf, n, &uc));
	datum_test(uc.channel_id == 4 && uc.nominal_hash_rate == 2.5e13f);

	n = unhex(hex_close_channel, buf, sizeof(buf));
	datum_test(datum_sv2_decode_channel_code(buf, n, &cc));
	datum_test(cc.channel_id == 4 && 0 == strcmp(cc.code.s, "shutdown"));

	n = unhex(hex_submit_standard, buf, sizeof(buf));
	datum_test(datum_sv2_decode_submit_shares(buf, n, false, &ss));
	datum_test(!ss.extended && ss.channel_id == 3 && ss.sequence_number == 9 && ss.job_id == 11);
	datum_test(ss.nonce == 0x0123456789abcdefULL && ss.ntime == ((5ULL << 32) | 1760000000ULL) && ss.extranonce.len == 0);
	datum_test(!datum_sv2_decode_submit_shares(buf, n, true, &ss)); // too short for extended
	datum_test(!datum_sv2_decode_submit_shares(buf, n - 1, false, &ss));

	n = unhex(hex_submit_extended, buf, sizeof(buf));
	datum_test(datum_sv2_decode_submit_shares(buf, n, true, &ss));
	datum_test(ss.extended && ss.channel_id == 4 && ss.ntime == 1760000000ULL);
	datum_test(ss.extranonce.len == 8 && ss.extranonce.b[0] == 0xa0 && ss.extranonce.b[7] == 0xa7);
	datum_test(!datum_sv2_decode_submit_shares(buf, n, false, &ss)); // trailing bytes for standard
	// a B0_32 longer than 32 is rejected even when the bytes are there
	buf[28] = 33;
	memset(&buf[29], 0xee, 33);
	datum_test(!datum_sv2_decode_submit_shares(buf, 29 + 33, true, &ss));
}

// messages the server sends: encode and compare with SRI bytes
static void datum_sv2_msg_tests_encode(void) {
	unsigned char buf[512];
	size_t n;

	{
		T_DATUM_SV2_SETUP_CONNECTION_SUCCESS m = { .used_version = 2, .flags = DATUM_SV2_FLAG_REQUIRES_EXTENDED_CHANNELS };
		n = datum_sv2_encode_setup_connection_success(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "020002000000"));
	}
	{
		T_DATUM_SV2_SETUP_CONNECTION_ERROR m = { .flags = 1 };
		datum_sv2_str_set(&m.error_code, "unsupported-feature-flags");
		n = datum_sv2_encode_setup_connection_error(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "0100000019756e737570706f727465642d666561747572652d666c616773"));
	}
	{
		T_DATUM_SV2_OPEN_CHANNEL_SUCCESS m = { .extended = false, .request_id = 7, .channel_id = 3, .extranonce_prefix = { .len = 4, .b = { 1, 2, 3, 4 } } };
		memcpy(m.target, target, 32);
		n = datum_sv2_encode_open_channel_success(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "0700000003000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f040102030400000000"));
		m.extended = true;
		m.channel_id = 4;
		m.extranonce_size = 8;
		n = datum_sv2_encode_open_channel_success(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "0700000004000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0800040102030400000000"));
	}
	{
		T_DATUM_SV2_OPEN_CHANNEL_ERROR m = { .request_id = 7 };
		datum_sv2_str_set(&m.error_code, "max-target-out-of-range");
		n = datum_sv2_encode_open_channel_error(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "07000000176d61782d7461726765742d6f75742d6f662d72616e6765"));
	}
	{
		T_DATUM_SV2_CHANNEL_CODE m = { .channel_id = 4 };
		datum_sv2_str_set(&m.code, "invalid-channel-id");
		n = datum_sv2_encode_channel_code(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "0400000012696e76616c69642d6368616e6e656c2d6964"));
	}
	{
		T_DATUM_SV2_SUBMIT_SHARES_SUCCESS m = { .channel_id = 4, .last_sequence_number = 9, .new_submits_accepted_count = 3, .new_shares_sum = 3000 };
		n = datum_sv2_encode_submit_shares_success(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "040000000900000003000000b80b000000000000"));
	}
	{
		T_DATUM_SV2_SUBMIT_SHARES_ERROR m = { .channel_id = 4, .sequence_number = 9 };
		datum_sv2_str_set(&m.error_code, "stale-share");
		n = datum_sv2_encode_submit_shares_error(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "04000000090000000b7374616c652d7368617265"));
	}
	{
		T_DATUM_SV2_NEW_MINING_JOB m = { .channel_id = 3, .job_id = 9, .has_ntime_start = true, .ntime_start = (1760000000ULL << 32) | 5 };
		memcpy(m.root, root, 32);
		n = datum_sv2_encode_new_mining_job(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "030000000900000001050000000078e768000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d"));
		// a future job leaves ntime_start out
		m.has_ntime_start = false;
		n = datum_sv2_encode_new_mining_job(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "030000000900000000000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d"));
	}
	{
		T_DATUM_SV2_NEW_MINING_JOB m = { .extended = true, .channel_id = 4, .job_id = 10 };
		memcpy(m.root, prev, 32);
		n = datum_sv2_encode_new_mining_job(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "040000000a00000000fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"));
		datum_test(0 == datum_sv2_encode_new_mining_job(&m, buf, n - 1)); // does not fit

		// and the decoder reads SRI's bytes back
		T_DATUM_SV2_NEW_MINING_JOB d;
		datum_test(datum_sv2_decode_new_mining_job(buf, n, true, &d));
		datum_test(d.extended && d.channel_id == 4 && d.job_id == 10 && !d.has_ntime_start && 0 == memcmp(d.root, prev, 32));
		datum_test(!datum_sv2_decode_new_mining_job(buf, n - 1, true, &d));
		buf[8] = 2; // an OPTION holds at most one value
		datum_test(!datum_sv2_decode_new_mining_job(buf, n, true, &d));
	}
	{
		T_DATUM_SV2_SET_NEW_PREV_HASH m = { .channel_id = 4, .job_id = 12, .ntime_start = (1760000000ULL << 32) | 5, .nbits = 0x17034219 };
		memcpy(m.prev_hash, prev, 32);
		n = datum_sv2_encode_set_new_prev_hash(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "040000000c000000fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0050000000078e76819420317"));
	}
	{
		T_DATUM_SV2_SET_TARGET m = { .channel_id = 4 };
		memcpy(m.maximum_target, target, 32);
		n = datum_sv2_encode_set_target(&m, buf, sizeof(buf));
		datum_test(same(buf, n, "04000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
	}
}

// client-side encoders reproduce the SRI bytes the decoders were checked against
static void datum_sv2_msg_tests_client_encode(void) {
	unsigned char buf[256];
	size_t n;
	T_DATUM_SV2_SETUP_CONNECTION sc = { .protocol = DATUM_SV2_PROTOCOL_MINING, .min_version = 2, .max_version = 2, .flags = 4, .endpoint_port = 23334 };
	T_DATUM_SV2_OPEN_CHANNEL oc = { .extended = true, .request_id = 7, .nominal_hash_rate = 1.0e14f, .min_extranonce_size = 8 };
	T_DATUM_SV2_SUBMIT_SHARES ss = { .extended = true, .channel_id = 4, .sequence_number = 9, .job_id = 11, .nonce = 0x0123456789abcdefULL, .ntime = 1760000000, .extranonce = { .len = 8 } };

	datum_sv2_str_set(&sc.endpoint_host, "10.0.0.5");
	datum_sv2_str_set(&sc.vendor, "Bitmain");
	datum_sv2_str_set(&sc.hardware_version, "S21");
	datum_sv2_str_set(&sc.firmware, "braiins-os-2026");
	datum_sv2_str_set(&sc.device_id, "dev-1");
	n = datum_sv2_encode_setup_connection(&sc, buf, sizeof(buf));
	datum_test(same(buf, n, hex_setup_connection));

	datum_sv2_str_set(&oc.user_identity, "bc1qtest.worker1");
	memcpy(oc.max_target, max_target, 32);
	n = datum_sv2_encode_open_channel(&oc, buf, sizeof(buf));
	datum_test(same(buf, n, hex_open_extended));

	for (int i = 0; i < 8; i++) ss.extranonce.b[i] = (unsigned char)(0xa0 + i);
	n = datum_sv2_encode_submit_shares(&ss, buf, sizeof(buf));
	datum_test(same(buf, n, hex_submit_extended));
	ss.extended = false;
	ss.channel_id = 3;
	ss.ntime = (5ULL << 32) | 1760000000ULL;
	n = datum_sv2_encode_submit_shares(&ss, buf, sizeof(buf));
	datum_test(same(buf, n, hex_submit_standard));
}

static void datum_sv2_msg_tests_header(void) {
	unsigned char h[6];
	T_DATUM_SV2_FRAME_HEADER d;

	// channel_msg is the MSB of the second byte on the wire
	datum_sv2_header_encode(h, 0, true, DATUM_SV2_MSG_SUBMIT_SHARES_EXTENDED, 0x123456);
	datum_test(h[0] == 0x00 && h[1] == 0x80 && h[2] == 0x1b && h[3] == 0x56 && h[4] == 0x34 && h[5] == 0x12);
	datum_sv2_header_decode(h, &d);
	datum_test(d.extension_type == 0 && d.channel_msg && d.msg_type == 0x1b && d.length == 0x123456);
	datum_test(datum_sv2_msg_is_channel_msg(DATUM_SV2_MSG_SET_NEW_PREV_HASH));
	datum_test(!datum_sv2_msg_is_channel_msg(DATUM_SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS));
	datum_test(!datum_sv2_msg_is_channel_msg(DATUM_SV2_MSG_SETUP_CONNECTION_SUCCESS));
}

void datum_sv2_msg_tests(void) {
	init_values();
	datum_sv2_msg_tests_header();
	datum_sv2_msg_tests_decode();
	datum_sv2_msg_tests_encode();
	datum_sv2_msg_tests_client_encode();
}
