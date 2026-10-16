# SV2's Mining Protocol on XBT

> **Where this document lives.** This is the specification for carrying XBT work over
> Stratum V2, not documentation of this gateway alone. It is kept here for now because
> I am unaware of a suitable official home for XBT protocol specifications.
> Whether it stays here or moves to a dedicated home is an open question for review.
> My personal view is that it should be re-homed; Datum Gateway is just one client
> of Stratum V2, not the spec itself.

> **No hardware speaks this yet.** At the time of writing, no XBT miner firmware supports
> Stratum V2, and none is known to be planned. This implementation was verified with CPU
> miners built on SRI's Stratum V2 libraries, on standard and extended channels, mining
> blocks that BLAKE2b Knots accepted. Whether SV2 support should land before any device
> can use it is an open question for review.

Stratum V2's Mining Protocol is used unchanged on XBT except for the five messages that
carry work: the two job messages, `SetNewPrevHash`, and the two share submissions. Those
keep their names, message types and roles; their fields describe XBT's BLAKE2b work
instead of the SHA256d header. Everything else is SV2 as specified: the Noise handshake,
framing, `SetupConnection`, channels, `SetTarget`, `UpdateChannel`, `CloseChannel`, and
the `SubmitShares.Success` / `SubmitShares.Error` replies.

There is nothing to negotiate with respect to which header is being used. A server serving
XBT work speaks these layouts. A device built for the SHA256d layouts cannot mine it,
just as a SHA256d device cannot mine XBT over Stratum V1.

A negotiation step, such as an extension, a flag or another protocol number, would not let
such a device mine either: it could only change where the device fails. On XBT these are
simply the layouts, not a variant of SHA256d's, so none is added. A device that requires
version rolling is refused at `SetupConnection`, since XBT work has no version field.

Status: first revision of this document, implemented by this gateway. This is unrelated to
SV2's protocol version, which stays 2.

## The work

What an XBT miner hashes is 80 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | prev hash, as given by `SetNewPrevHash` |
| 32 | 8 | nonce, rolled by the miner |
| 40 | 8 | time field, little-endian (below) |
| 48 | 32 | merkle root |

`hash = BLAKE2b-256(work)`. A share meets a target when the hash, read with its first
byte most significant, is at or below the target (`U256`, little-endian, as everywhere in
SV2). Share targets from this gateway are powers of two, so the check is a count of
leading zero bits.

The node applies a further mask to the hash before comparing it to the block target. The
mask never touches the leading bits a share target looks at, so miners do not need it;
the gateway applies it when it checks shares.

The time field is not the block time; the block time is fixed inside the commitment. Each
job gives the 8 bytes to put in the time field, `ntime_start`, the same value an SV1 XBT
miner gets as its 16-hex `ntime`. Send them back as given. Bytes 0 to 3 are a time offset:
when the commitment allows hasher time rolling, the node adds it to the block time, so a
miner may change them then, and the gateway checks the resulting time against the node's
limits. Otherwise the node ignores them.

The merkle root commits to everything else in the block (version, height, the
transactions' merkle root, bits, the coinbase with the share's difficulty) plus a
12-byte extranonce:

```
merkle_root = BLAKE2b-256( 0x00 || 0x000000 || commitment || 0x00000000 || extranonce )
```

`commitment` is 32 bytes and `extranonce` 12, so the hashed leaf is 52 bytes. The
version is inside the commitment: XBT work has no version rolling, and none of these
messages carries a version.

## Channels

- Standard (`OpenStandardMiningChannel`): the gateway computes the merkle root, so the
  device only rolls the nonce. The whole 12-byte extranonce is the gateway's;
  `extranonce_prefix` in the Success reply carries it.
- Extended (`OpenExtendedMiningChannel`): the device gets the commitment and builds the
  merkle root itself. `extranonce_prefix` is 4 bytes and the device rolls the other 8
  (`extranonce_size` = 8).

`target` in the Success reply, `SetTarget` and `UpdateChannel.max_target` are targets
as defined above.

## Messages

Message types, the `channel_msg` bit and directions are those of SV2's Mining Protocol.
Field types are SV2's.

### NewMiningJob (0x15), server to standard channel

| Field | Type |
|---|---|
| channel_id | U32 |
| job_id | U32 |
| ntime_start | OPTION[U64]: the 8 time bytes. Empty for a future job, which is mined with `SetNewPrevHash.ntime_start` once that message names it |
| merkle_root | U256 |

### NewExtendedMiningJob (0x1f), server to extended channel

| Field | Type |
|---|---|
| channel_id | U32 |
| job_id | U32 |
| ntime_start | OPTION[U64], as in `NewMiningJob` |
| commitment | U256 |

### SetNewPrevHash (0x20), server to channel

| Field | Type |
|---|---|
| channel_id | U32 |
| job_id | U32 |
| prev_hash | U256: the 32 bytes the work starts with, in work order |
| ntime_start | U64: the 8 time bytes for the job it activates |
| nbits | U32: the block's bits, informational |

### SubmitSharesStandard (0x1a), standard channel to server

| Field | Type |
|---|---|
| channel_id | U32 |
| sequence_number | U32 |
| job_id | U32 |
| nonce | U64: the 8 nonce bytes, little-endian |
| ntime | U64: the 8 time bytes, little-endian |

### SubmitSharesExtended (0x1b), extended channel to server

| Field | Type |
|---|---|
| channel_id | U32 |
| sequence_number | U32 |
| job_id | U32 |
| nonce | U64 |
| ntime | U64 |
| extranonce | B0_32: exactly `extranonce_size` bytes |

The server answers both with `SubmitShares.Success` or `SubmitShares.Error`.
