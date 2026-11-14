# RE-008: node #115 digest quorum store (64th stage): who adds a vote

- Component ID: abci. Question: #6051 found that the walker `0x5374b70` resolves per-height values in store `+0x18` by a two-thirds compare. It left open who adds votes to that map and what a vote carries.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6049 and #6051 and does not depend on their files.
- Claim status: instruction bytes, offsets, constants, slot relocations and call censuses are observations. "Vote", "signer", "sender", "signature", "validator set" and "message hash" are inferred labels from the control flow, the 20-byte compares and the BLAKE3 calls. The binary was not executed.
- Scope included: the four handlers' check and record build, the store update `0x5afa7f0` up to its calls, the entry of the vote insert `0x537b870`. Scope excluded: the bodies of `0x1536a90`, `0x3c3a3f0`, `0x3c3d240`, `0x36ca5b0`, `0x57c9430` and `0x537b870` beyond its entry, the second-store update `0x5afadd0`, the handlers' callers (action dispatch; no action names are given), and the writer of store `+0x38`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/digest_quorum_vote_insert_115.py --check
python3 -m unittest tests.test_digest_quorum_vote_insert_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: four handlers, two stores, two layouts

| Handler | Store | `r8` | `r9` | `ecx` byte | Update |
|---|---|---|---|---|---|
| `0x5862560` (A) | box `+0x3d98` | box `+0x3f08` | box `+0xd88` | box `+0xb9a` | `0x5afa7f0` |
| `0x5862770` (B) | box `+0x4908` | box `+0x4a78` | box `+0x18f8` | box `+0x170a` | `0x5afa7f0` |
| `0x5869400` (A) | box `+0x3e50` | box `+0x3f08` | box `+0xd88` | | `0x5afadd0` |
| `0x5869610` (B) | box `+0x49c0` | box `+0x4a78` | box `+0x18f8` | | `0x5afadd0` |

Layout B offsets are layout A plus `0xb70` (#6006). `0x5afa7f0` is called only by the first two handlers, `0x5afadd0` only by the second two.

## Evidence 2: the handler checks the signer

In `0x5862560` (B is byte-identical in shape):

1. `0x58625b1` calls `0x38d2920`, which serialises the message and hashes it with BLAKE3 update/finalize (slots `0x64df510` → `0x160b3a0`, `0x64df518` → `0x160bcd0`, the #6024 pair).
2. `0x58625c1` calls slot `0x64e0ad8` (→ `0x1536a90`) with message `+0x28` and that hash. On Err (`cmp byte [rsp+0x20], 1`) it returns error tag `0x7e`.
3. It compares the returned 20 bytes (16 + 4 with `pcmpeqb`) with the sender at `r15`; on mismatch it returns error tag `0x12e`.
4. A height `>= 0x0ccccccccccccccc` is rejected.

Inference: message `+0x28` is a signature, `0x1536a90` recovers its signer, and only the signer may submit its own vote.

## Evidence 3: the vote record

The handler builds the record at `rsp+0xb0` and passes it as `rdx`:

| Offset | Content |
|---|---|
| `+0x0` | message `+0x28` |
| `+0x8` | height |
| `+0x10..+0x30` | message `+0x0..+0x20` (the digest) |
| `+0x30..+0x44` | the 20-byte sender |

## Evidence 4: the store update `0x5afa7f0`

- `0x5afa84f` calls slot `0x64e6470` (→ `0x3c3a3f0`) with (`r9`, `ecx`, sender) and keeps the boolean.
- When store byte `+0x90` is 0, the record height equals box `+0x10` (initial height) and that boolean is true, it sets store `+0x91` = 1 and copies the digest to store `+0x92..+0xb2`.
- `0x5afa8b9` calls slot `0x64e4f18` (→ `0x3c3d240`), then searches a B-tree at `r9 +0x30` with 20-byte `memcmp` keys (`mov edx, 0x14`).
- `0x5afa9e8` calls slot `0x64e6478` (→ `0x36ca5b0`) with `[r8+0x58]` and the sender; a tag of `0x1a2` carries 32 bytes. `r8 +0x58` is the same argument the walker passes to its stake check (#6051).
- It then calls `0x57c9430(store, height, digest)` and `0x537b870`, whose only call is `0x5afab8f`. `0x537b870` moves its store argument to `r13` and takes store `+0x18` at `0x537b96c`.
- It returns tag `0x1a2` with byte `+0x2` = changed, or error tag `0x95`.

## Census

The tool scans `.text` once for E8 calls and checks: `0x5afa7f0` at `0x58626e3`, `0x58628f3`; `0x5afadd0` at `0x5869583`, `0x5869793`; `0x537b870` at `0x5afab8f`; `0x5862560` at `0x550ed20`, `0x55fa523`; `0x5862770` at `0x54f86b0`, `0x55fb5f3`. It also checks six slot relocations.

## Implementation and comparison

The tool pins 51 instruction byte runs, 7 direct calls, 6 slot calls and 6 relocations, then recomputes the call census. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: entering the recovery and lookup bodies (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: a vote is (sender, height, digest, signature). The handler checks that the signature's signer is the sender, then the update adds the vote to store `+0x18` through `0x537b870`. A vote at the initial height also records its digest at store `+0x92`.
- Limits: the body of `0x537b870` beyond its entry, so how a vote becomes an inner-map item; what `0x3c3a3f0`, `0x3c3d240` and `0x36ca5b0` return beyond the shapes above; `0x57c9430`; the second-store update `0x5afadd0`; the handlers' callers; the writer of f64 store `+0x38` (no direct `+0x3dd0`/`+0x4940` store found; one 16-byte read at `0x55f13ab`).
- Next lead: the inner-map write in `0x537b870`.
