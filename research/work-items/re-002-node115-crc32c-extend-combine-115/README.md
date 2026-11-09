# RE-002 · Node #115 RocksDB CRC-32C slow path: ExtendImpl + Crc32cCombine

Component: storage (RocksDB checksums). Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Upstream base commit `0781ce048`. Disassembly: GNU objdump 2.42.
Model and tests: `tools/crc32c_extend_combine115.py`,
`tests/test_crc32c_extend_combine115.py` (2,400 deterministic cases).

## What is reconstructed

Two vendored RocksDB functions from `librocksdb-sys`, both with FDE
ranges that match the vendor census exactly and bodies that hash exactly
to the census `target_body_sha256` values (see [functions.tsv](functions.tsv)):

* `rocksdb::crc32c::ExtendImpl<Slow_CRC32>` at `0x61c21d0..0x61c23b9`
  (489 bytes, census `node115-vendor-61c21d0`, body SHA-256
  `84b07761adc5476aeaa34ab231b330bd77f0b1fca654c2b6772f752d38d704a8`):
  the table-driven CRC-32C (Castagnoli, reflected polynomial
  `0x82f63b78`) extend. Pre/post inversion (`~crc` in, `~state` out),
  byte-at-a-time prologue to the next 16-byte boundary, slicing-by-4
  main loop (16 bytes, then 8 bytes per round), byte-at-a-time tail.
* `rocksdb::crc32c::Crc32cCombine` at `0x61c2600..0x61c26c9`
  (201 bytes, census `node115-vendor-61c2600`, body SHA-256
  `09b69c91e274c5adf31eb408cf6a7fc004f4db177f34b61dc053cff1b8b4480c`):
  `combine(crc1, crc2, len2) = crc2 ^ advance_raw(crc1, 8*len2)`, where
  `advance_raw` is the reflected one-bit CRC step. A 32-entry `.rodata`
  table at `0x97cde0` supplies the polynomial for `x^(32*2^p)` for each
  set bit `p` of `len2>>2`; for `len2 % 4 != 0` the remainder is
  advanced first through the public Extend entry over zero bytes.

Also bound in the packet: the public `crc32c::Extend` entry stub at
`0x61c25f0` (16 bytes, `jmp [0x6508908]`), and the pointer initializer
at `0x61c26d0..0x61c26e3` (19 bytes, FDE-verified) which stores the
address of `ExtendImpl` into the BSS slot `0x6508908`.

## Tables

`T0` at `0x97dae0` is the standard CRC-32C base table generated from
the polynomial. `T1`/`T2`/`T3` at `0x97d6e0`/`0x97d2e0`/`0x97cee0`
equal `T0` advanced by 1/2/3 zero bytes respectively, verified for all
256 entries (see [tables.tsv](tables.tsv); raw tables committed as
`crc32c_slice_t*_table115.bin`). The combine table's entry 0 is the
polynomial itself; entry 31 repeats it. The packet records the table
bytes and SHA-256 values; no recurrence for the combine table beyond
entry 0 is claimed.

## Why the slow path is the live path

`IsFastCrc32Supported` at `0x61c2400` returns the string
"Not supported on x86" (reconstructed in an earlier packet). The only
writer of the Extend function-pointer slot found in `.text` stores
`ExtendImpl<Slow_CRC32>`, and the slot has no dynamic relocation
(`.rela.dyn`/`.rela.plt` checked), so the table-driven slow path is the
`Extend` that the 26 call sites in [callers.tsv](callers.tsv) actually
reach. `ExtendImpl` itself has no direct `E8` call site in `.text`.

## Callers

26 direct `E8` sites call the Extend entry stub (BlobLog encode/decode,
`log::Reader`/`log::Writer`, `WritableFileWriter::Pad`,
`ComputeBuiltinChecksum` / `ComputeBuiltinChecksumWithLastByte`,
`Crc32cCombine`'s own slow path, and others — see
[callers.tsv](callers.tsv)). `Crc32cCombine` has exactly 3 call sites
(`0x5f03bf2`, `0x6050d7d`, `0x6054a79`), all of the form
`combine(prev_crc, Extend(0, buf, len), len)`.

## Degenerate case (verified, not smoothed over)

`Crc32cCombine` has no `len2 == 0` early return: `combine(crc1, crc2, 0)`
returns `crc1 ^ crc2`. The concatenation identity
`combine(Extend(0,A), Extend(0,B), |B|) = Extend(0, A||B)` holds for
`|B| > 0` (200 random pairs, 0 mismatches) and fails at `len2 == 0`
unless `crc2 == 0`. The three observed call sites pass
`crc2 = Extend(0, buf, len2)`, which is `0` when `len2 == 0`, so the
result is correct there. The site at `0x6054a79` is reachable with
`len2 == 0` (fall-through when `rbp == 0`); the `crc2` value on that
path is not established from the excerpt and is recorded as an unknown.

## Verification

* 1,200 Extend cases (transliteration vs independent bit-by-bit
  reference, lengths 0..600 plus boundary lengths, five data alignments
  to exercise the prologue), 0 mismatches.
* 1,200 Combine cases (transliteration vs independent GF(2) advance
  model, `len2` 0..1000 plus boundary lengths), 0 mismatches.
* 640 inner-loop checks: the combine table step equals
  `advance_raw(crc, 32*2^p)` and advances the state by 32 bits, for all
  `p` in 0..31.
* Known vectors: `Extend(0, "") = 0`, `Extend(0, "123456789") =
  0xE3069283` (published CRC-32C check value); chained extends equal one
  extend over the concatenation.
* All 2,400 cases are committed in [cases.tsv](cases.tsv)
  (inputs as SHA-256 of the data, outputs as hex).

## Unknowns (kept separate from observations)

* Which initializer calls the pointer-init function at `0x61c26d0`:
  no direct `E8` caller exists in `.text` and the address is not in
  `.init_array` (168 entries checked). The slot is written by program
  startup code, not the dynamic linker.
* The `crc2` value on the `len2 == 0` path into `Crc32cCombine` at
  `0x6054a79` (see above).
* No recurrence for the combine table beyond entry 0 is claimed.

## Reproduction

Run from the repository root with the node artifact materialized
(`work/hl-node-115.bin` here; the canonical path is
`artifacts/node/115/hl-node`):

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  work/hl-node-115.bin' | sha256sum -c -
objdump -d --start-address=0x61c21d0 --stop-address=0x61c23b9 work/hl-node-115.bin
objdump -d --start-address=0x61c2600 --stop-address=0x61c26c9 work/hl-node-115.bin
objdump -d --start-address=0x61c25f0 --stop-address=0x61c26e3 work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin | grep -E 'pc=00000000061c(21d0|2600|26d0)'
python3 -m pytest tests/test_crc32c_extend_combine115.py -q
python3 tools/verify_packets.py
```

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM, so
`make verify` / `make test` / `make catalogue-check` could not be run
in a tooled environment; the packet tests above and
`tools/verify_packets.py` were run instead. The binary was not executed;
all checks are static reads plus deterministic Python models.
