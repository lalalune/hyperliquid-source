# RE-009 follow-up: what blake3 hashes inside `0x3269ae0`

**Target:** `artifacts/node/94/hl-node`, SHA-256 `3b7179cd…c0459f`. The evidence is static only. Nothing was executed and nothing was fetched from the network.

**Function:** FDE `0x3269ae0..0x326a6ee`. Its only rel32 callers are `0x326e4bb` and `0x32fc41f`, found by a full `.text` scan.

**Context:** Location `l1/src/evm/evm_db.rs:154`. The merged RE-009 packet already lists this function as one that references `/lt_hashes.json` and calls blake3 through slot `0x57700c8`. It does not say what bytes are hashed or where the digest goes. This packet answers that.

## Claim (scoped)

There are three blake3 rounds. Each has the same shape:

1. A DB-wrapper call.
2. `memset(buf, 0, 0x810)`.
3. A producer call `(rdi=buf, rsi=src, edx=1000000, rcx=scratch)`.
4. blake3 `0x57700c0`.
5. `update(rsp+0xa60, buf, 0x800)`.
6. `finalize(out32, rsp+0xa60)`.

| round | DB wrapper (esi) | producer (Location) | hashed bytes | update | finalize → slot |
|---|---|---|---|---|---|
| 1 | 0x3269c5c → 0x358cea0 (0x18) | 0x37d3070 (rocksdb-0.21.0 db_iterator.rs:109) | rsp+0x150, 0x800 | 0x3269d96 | 0x3269dac → rsp+0x2e90 |
| 2 | 0x3269e77 → 0x358d720 (0x19) | 0x37d3bd0 (same) | rsp+0x150, 0x800 | 0x3269fb1 | 0x3269fc7 → rsp+0x2580 |
| 3 | 0x326a086 → 0x358d2e0 (0x1a) | 0x37d2550 (same) | rsp+0x3798, 0x800 | 0x326a1bd | 0x326a1d3 → rsp+0x150 |

Each round hashes exactly the first 0x800 bytes of its own 0x810-byte buffer. The rounds are separate hashers, not one chained hash. The order is 1, 2, 3.

Each 32-byte finalize output is overwritten before it is read:

- The store `mov [slot],r14; mov [slot+8],ebp` writes the Instant::now result.
- A `memcpy(slot, …, 0xf8)` then follows. It covers all 32 bytes.

The pinned sites are:

| slot | Instant::now store | memcpy |
|---|---|---|
| 0x2e90 | 0x3269dcb | 0x3269e13 |
| 0x2580 | 0x3269fe0 | 0x326a025 |
| 0x150 | 0x326a1ec | 0x326a22e |

The 0x810-byte buffers themselves are what get copied, with `memcpy 0x810`, into the records that are passed to `0x32699c0`. That function is the `/lt_hashes.json` writer (`evm/hash.rs:69`), called at `0x326a2e0`. **No blake3 digest reaches that writer.**

## What this does not claim

- What the producers compute. That the buffers are LtHash state is an inference, not a claim.
- What `1000000` means.
- The layout of the 0x10 tail.
- What the DB codes 0x18/0x19/0x1a mean. Open PR #245 labels these windows.
- That `0x14f93e0` and `0x14fa010` are blake3 update and finalize. This is inferred from the blake3 FDEs and the argument shapes, not proven.
- Any runtime behaviour. "The hash is timing-only" is not proven.

## Prior work / dup check

- **#158** (open): leaves RAW_HASH_BYTES and DIGEST_BYTES unresolved, and claims no digest.
- **#154** (open): reworks the hasher inventory.
- **#245** (open, RE-001 DB-code routing): same FDE `0x3269ae0`, but only the DB-wrapper constant-code windows (esi 0x18/0x19/0x1a). This packet takes those call sites as anchors and makes no claim about what the codes mean.

None of these pins the hash input or where the digest goes.

## Files

- `tools/evm_db_blake3.py`
- `evm-db-blake3.json`
- `verify.py`
- `independent_verify.py` (raw ELF parsing; does not import the tool)
- `MANIFEST.sha256`
- `tests/test_evm_db_blake3.py`

The merged RE-009 JSON files are left unchanged. They serve as the negative control.

## Reproduce

```
python3 -I -B research/work-items/RE-009-evm-db-blake3/verify.py
python3 -O -B research/work-items/RE-009-evm-db-blake3/verify.py
python3 -I -B research/work-items/RE-009-evm-db-blake3/independent_verify.py
```

`evm-db-blake3.json` has sha256 `d0047969a9226409e8d74480d57df9cd76bd4c8d91fcbbb38792c9a85fbead4e`. It is identical under PYTHONHASHSEED 0, 7 and 99.
