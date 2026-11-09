# RE-001: pin node #115 DBImpl constructor compression-support logging

Task RE-001. Node #115 (`work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Inside `rocksdb::DBImpl::DBImpl` (census `node115-vendor-5d85480`,
FDE `0x5d85480..0x5d878e2`, body SHA-256 verified against the census
target), a loop walks the CompressionType registry's element list and
logs one line per codec: `"\t%s supported: %d"`.

## What is pinned

- Registry: the CompressionType named-enum registry at `0x6507120`
  (option type 13), head at `+0x10`. Its ten entries are already
  reconstructed in the merged packet
  `research/work-items/RE-001-enum-registries-115`; this packet adds
  the supported-flag decision table and the log call, which that
  packet does not decode (it records only the value filter).
- Node layout: next `+0x0`, name string data pointer `+0x8`, name
  size `+0x10`, value byte `+0x28`. The parse helper `0x60be400`
  reads the same offsets, and the kind lookup at `0x60bb1c0`
  compares the byte at `+0x28`.
- Filter: a node is logged only when `(u8)(value - 1) <= 0xfd`, i.e.
  value in 1..254. `kNoCompression` (0) and
  `kDisableCompressionOption` (255) produce no log line.
- Decision table (value -> logged supported flag):
  - 1..5 (Snappy, Zlib, BZip2, LZ4, LZ4HC): 1. The code sets the
    flag to `(value != 6)`.
  - 6 (kXpressCompression): 0. Xpress is logged as not supported.
  - 7 (kZSTD): the flag is `(version_helper() > 799)`. The helper
    at `0x620dd50` returns the constant 10506 (`0x290a`), so the
    flag is 1 in this binary.
  - 64 (kZSTDNotFinalCompression): 1. The kind > 7 branch sets the
    flag to `(value == 0x40)`.
  - 8..63, 65..254 (no registry entry today): 0 by the same
    `(value == 0x40)` rule; a code-path rule only.
- Log call: level 5, logger in `r12`, format `"\t%s supported: %d"`
  (`.rodata` `0x433f10`), name pointer, supported flag; target
  `0x5fceda0`. The format string is referenced from nowhere else in
  `.text` (whole-`.text` rip-relative scan: sole site `0x5d87340`).
- Version helper `0x620dd50` (9 bytes: `endbr64; mov $0x290a,
  %eax; ret`): returns the constant 10506. The same threshold 799
  (`0x31f`) is used at two other call sites (`0x616c43a`, a
  compression-type dispatch on kind 7, and `0x60e580a`/`0x60e580f`,
  two back-to-back calls). Inference only: 10506 is
  `ZSTD_versionNumber()` for zstd 1.5.6 under the public
  major\*10000 + minor\*100 + patch encoding, and 799 is 0.7.99 in
  the same encoding. The helper's source-level identity is not
  claimed.

## Files

- `dbimpl_compression_support115.hex`: the 129 raw bytes of the
  loop's main region (`0x5d872db..0x5d8735c`).
- `dbimpl_compression_support115.objdump.txt`: verbatim objdump of
  the loop's main region, the two out-of-line branch blocks
  (`0x5d87499..0x5d874bd`), and the version helper
  (`0x620dd50..0x620dd59`).
- `records.json`: semantic records only (decision table, node
  layout, hashes, unknowns).

## Unknowns

- The source-level name of the version helper at `0x620dd50`
  (inference only, above).
- The identity of the logger held in `r12` (set by the enclosing
  constructor outside this loop; not verified here).
- The runtime order of the log lines (the loop walks the
  registry's element-list order; no claim it matches insertion
  order).
- The source-level name of this logging loop beyond the census
  label of the enclosing constructor.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. Claims rest on objdump
disassembly, direct byte reads and SHA-256 hashes from
`work/hl-node-115.bin`, plus whole-`.text` scans.
