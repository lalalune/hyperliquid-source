# RE-002: node #115 RocksDB CRC32C extend step

This packet reconstructs one bounded node #115 behavior: the table-driven
CRC32C update at `0x61c21d0` (FDE `0x61c21d0..0x61c23b9`), attributed by the
vendor census to `rocksdb::crc32c::ExtendImpl<Slow_CRC32>` (librocksdb-sys),
so an independent reconstruction can reproduce its result on any input.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, table bytes, FDE extent, window hashes
  and the observed register/memory operations are observations. The C++
  symbol attribution comes from the vendor census
  (`research/work-items/RE-002-node115-vendor-census/census.json`) and the
  prose names for the phases are inferences from the disassembly.
- Scope included: the one function, its four slicing tables, the six
  byte-checked windows, the fn-pointer registration, and the 2400-case
  model cross-check. Excluded: the neighbouring CRC32C routine at
  `0x61c2600`, the consumer of the fn-pointer slot, every other checksum
  path, and any claim about which files or blocks the node checksums.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/crc32c_extend115.py --verify
python3 tools/crc32c_extend115.py --out research/work-items/re-002-node115-crc32c-extend-115
python3 -m unittest tests.test_crc32c_extend115
(cd research/work-items/re-002-node115-crc32c-extend-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`crc32c_extend(crc: u32, buf: *const u8, len: usize) -> u32`, observed
register use: `edi` = incoming crc, `rsi` = buffer pointer, `rdx` =
length, `eax` = updated crc. Entry complements the incoming crc
(`mov %edi,%eax; not %eax` at `0x61c21d4`), the body updates the
complemented value, and the exit complements again (`not %eax` at
`0x61c23b5`). The empty input is therefore the identity, and
`extend(0, b"123456789")` is the CRC32C check value `0xe3069283`.

### Loop structure

| Phase | Window | Observation |
| --- | --- | --- |
| Head | `0x61c21ef..0x61c221d` | Byte-at-a-time T0 step while the pointer advances to the next 16-byte boundary (`lea 0xf(%rsi); and $-16`); skipped when the end precedes that boundary. |
| 16-byte blocks | `0x61c221d..0x61c22ff` | Slicing-by-4: each 4-byte little-endian word is xored into the running crc, then its bytes fold through T3/T2/T1/T0 (byte 0 through T3, byte 3 through T0). Runs while more than 15 bytes remain. |
| 8-byte blocks | `0x61c2309..0x61c2387` | Same slicing-by-4 step, two words per iteration. Runs while more than 7 bytes remain. |
| Tail | `0x61c238c..0x61c23b9` | Byte-at-a-time T0 step for the remaining bytes. |

All four phases implement the same update; only the loop structure
differs, so the result does not depend on the caller's buffer alignment.
The Python model in `tools/crc32c_extend115.py` implements the
slicing-by-4 update and the byte step, and agrees with an independent
bit-by-bit reference on all 2400 deterministic cases (seed 20261109;
boundary lengths 0–4096 plus random lengths up to 8192 and random
incoming crc values). `cases.tsv` records the 23 boundary-length cases
plus the first 41 generated rows; `result.json` carries the aggregate
digest over all 2400 case results.

### Tables

| Table | Address | Derivation |
| --- | --- | --- |
| T0 | `0x97dae0` | Plain CRC32C table generated from reflected polynomial `0x82F63B78`. |
| T1 | `0x97d6e0` | First slicing derivation of T0. |
| T2 | `0x97d2e0` | Second slicing derivation. |
| T3 | `0x97cee0` | Third slicing derivation. |

Every table byte in the binary matches the generated values; each 1 KiB
table is SHA-256-pinned in `tables.tsv`.

### Registration

The tiny initializer at `0x61c26d0` (FDE `0x61c26d0..0x61c26e3`) stores
the function address into the writable slot at `0x6508908`. No direct
`call` to `0x61c21d0` exists anywhere in `.text`, and a rip-relative scan
of `.text` found no reader of that slot, so the consumer is recorded as
unknown in `records.json`, not claimed. The RocksDB
`FileChecksumGenCrc32cFactory` typeinfo recorded in earlier packets is
consistent with this being the file-checksum CRC32C, but this packet does
not establish that link.

### Related unknown

The neighbour at `0x61c2600` (FDE `0x61c2600..0x61c26c9`) is a separate
CRC32C routine: it applies the polynomial immediate `0x82F63B78`
bit-by-bit over u32 words (with a byte head handled by a call to
`0x61c25f0`). It is not reconstructed here.

## Files

- `tables.tsv` — the four slicing tables with addresses and hashes.
- `windows.tsv` — the six byte-checked instruction windows.
- `cases.tsv` — 64 recorded cases (boundary lengths + first generated rows).
- `result.json` — function/FDE pins, check value, 2400-case summary.
- `records.json` — semantic records only (function, tables, windows,
  registration, case summary, unknowns).
