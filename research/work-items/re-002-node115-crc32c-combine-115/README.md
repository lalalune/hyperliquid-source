# RE-002: node #115 RocksDB CRC32C combine step

This packet reconstructs one bounded node #115 behavior: the CRC32C
combine at `0x61c2600` (FDE `0x61c2600..0x61c26c9`), attributed by the
vendor census to `rocksdb::crc32c::Crc32cCombine` (librocksdb-sys), so an
independent reconstruction can reproduce its result for any inputs.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, table bytes, FDE extent, window hashes
  and the observed register/memory operations are observations. The C++
  symbol attribution comes from the vendor census
  (`research/work-items/RE-002-node115-vendor-census/census.json`, record
  5428, whose `start`/`end` are exactly `0x61c2600`/`0x61c26c9` and whose
  `target_body_sha256` matches the body hash in `result.json`). The prose
  names for the phases are inferences from the disassembly.
- Scope included: the one function, its GF(2) power table, the seven
  byte-checked windows, the head call through the registered extend
  function, the one located caller, and the 2400-case model cross-check.
  Excluded: every other checksum path, and any claim about which files or
  blocks the node checksums with the combined value.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/crc32c_combine115.py --verify
python3 tools/crc32c_combine115.py --out research/work-items/re-002-node115-crc32c-combine-115
python3 -m unittest tests.test_crc32c_combine115
(cd research/work-items/re-002-node115-crc32c-combine-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`crc32c_combine(crc1: u32, crc2: u32, len: usize) -> u32`, observed
register use: `edi` = crc1, `esi` = crc2, `rdx` = length, `eax` = result.
It returns `crc2 ^ advance(crc1, len)`, where `advance` feeds `len` zero
bytes through the CRC32C update starting from the raw state `crc1`. The
function does no complementing of its own; it operates on raw states, and
`len == 0` returns `crc1 ^ crc2`.

### Concatenation reading

The function is the combine half of a concatenation, but the exact
stored-form relation needs one extra term, verified on 300 random splits
and pinned in `result.json` for `"123456789"` split as `"12345"` +
`"6789"`:

```text
extend(0, X || Y) == ~combine(~extend(0, X), ~extend(0, Y), len(Y))
                     ^ advance(0xFFFFFFFF, len(Y))
```

A bare `~combine(~s1, ~s2, n)` is NOT the stored CRC of the
concatenation; for the pinned split it gives `0xab61d944`, and the
correction term `advance(0xFFFFFFFF, 4) = 0xb798b438` brings it to the
stored CRC `0xe3069283`. Equivalently, if `crc1` is the raw state after
`X` and `crc2` is the raw CRC of `Y` computed from a zero initial state,
the result is the raw state after `X || Y`.

### Two paths

| Path | Window | Observation |
| --- | --- | --- |
| Misaligned head | `0x61c26ae..0x61c26c9` | When `len % 4` is non-zero, the function calls the registered extend function (the `0x61c21d0` routine) through the PLT stub at `0x61c25f0`, which jumps through the writable `.bss` slot at `0x6508908`. The initializer at `0x61c26d0` stores `0x61c21d0` into that slot. The call passes `~crc1` with a zeroed stack word as the buffer, so the double complement cancels and the result is the raw advance by `len % 4` zero bytes. |
| Word loop | `0x61c262f..0x61c26ae` | The remaining `len / 4` words are handled by binary decomposition: `tzcnt` finds the lowest set bit of the remaining word count, the matching table entry is loaded, and the inner 32-step loop multiplies the state by that entry (GF(2) polynomial multiply with the `0x82F63B78` reduction). Each set bit at position `i` advances the state by `32 * 2**i` zero bits. |

The Python model in `tools/crc32c_combine115.py` implements both paths
literally from the disassembly, using the table bytes as read from the
binary, and agrees with an independent bit-by-bit reference on all 2400
deterministic cases (seed 20261109; boundary lengths 0–4096 plus random
lengths up to 8192 and random crc values).

### Table

| Table | Address | Derivation |
| --- | --- | --- |
| POW | `0x97cde0` | 64-entry GF(2) power table: entry `i` advances the raw state by `32 * 2**i` zero bits. Verified: the effective factor of entry `i` equals the bitwise advance by that many zero bits, and the squaring chain between consecutive entries holds for `i = 0..60`. Entries 62–63 are zero padding, never indexed for any `size_t` length. |

The table region ends just before the T3 slicing table at `0x97cee0`
used by the neighbouring extend routine.

### Consumer

One in-binary caller is located:
`rocksdb::WritableFileWriter::Append` (cold part, FDE
`0x6054680..0x605518b`) calls `0x61c2600` at `0x6054a79` with the running
checksum from `0xd4(%rbx)`, the new chunk's checksum from the stack, and
the chunk length in `rbp`, storing the combined checksum back to
`0xd4(%rbx)`. No exhaustive call census was run, so other callers may
exist.

## Files

- `tables.tsv` — the power table with address and hash.
- `windows.tsv` — the seven byte-checked instruction windows.
- `cases.tsv` — 64 recorded cases (boundary lengths + first generated rows).
- `result.json` — function/FDE pins, check values, 2400-case summary,
  head-call and consumer records.
- `records.json` — semantic records only (function, table, windows,
  head call, consumer, case summary, unknowns).
