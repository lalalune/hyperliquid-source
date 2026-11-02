# RE-001: BlockCache dispatch getters at 0x514e7e0 / 0x514e870 / 0x514e900 (node #94)

Bounded question: what do node #94 functions 0x514e7e0, 0x514e870 and
0x514e900 do with their outer argument — how does each combine the
BlockCache chain lookup 0x514e550 with a sentinel-compared
wrapper-chain dispatch walk, and which callers consume them?

## Composed rule

- Each getter takes (outer rdi, out pointer rsi; the out pointer is
  preserved in rbx) and first calls the BlockCache chain lookup
  0x514e550 on the outer object, passing it unchanged. The lookup
  returns the matching record's +0x20 first qword, or 0 on a miss.
- A null lookup result returns 0 with *out untouched.
- Otherwise the getter walks a chain of wrapper nodes. A wrapper
  holds an inner-object pointer at +0x00 and the next wrapper at
  +0x38; the dispatch slot of a wrapper is `[inner + slot]`, where
  slot is 0x70 (getter 0x514e7e0), 0x78 (0x514e870) or 0x98
  (0x514e900).
- The walk compares each visited node's dispatch slot against the
  contents of the getter's sentinel cell: 0x5777a28 (slot 0x70),
  0x5777a78 (slot 0x78), 0x5777a38 (slot 0x98). The first
  comparison reads the cell; later comparisons compare against the
  first dispatch value, which provably equals the cell contents on
  those paths. While the slot equals the sentinel the walk
  advances, at most four times.
- The first non-sentinel slot is called with the wrapper, its
  result is stored at *out, and the getter returns 1. The fifth
  node is called unconditionally, without a sentinel comparison.
- The three getters agree instruction for instruction apart from
  the slot offset, the sentinel cell, and their call-site
  addresses. They contain no PLT calls and no stack canary; the
  only call in each getter body besides the indirect dispatch
  calls is the direct rel32 call to the lookup.

This item is the consumer side of the RE-001-blockcache-chain-lookup-94
packet, which cited these three functions only as callers of
0x514e550 (census only) and modelled the lookup itself. The lookup,
its helper, its walker and its sentinel are cited here as callees
only, not re-claimed; the sentinel cells are shared with
RE-001-chain-dispatch-94, which binds the same three cells for the
current-head getters, and are likewise cited, not re-claimed. The
new claim is the three getters' own BlockCache-headed dispatch
walk, their null-lookup arms, and their (empty) caller census.

## Callers (consumers only)

A full .text direct-rel32 scan, a full .text rel32 tail-jump scan
and a whole-file qword scan found no direct caller, no tail jump
and no absolute pointer to any of the three getters, so no caller
is claimed and the reaching path is left unclaimed — the same
position as the current-head getters of RE-001-chain-dispatch-94.
(Relative-relocation tables, if any, were not scanned.)

## Evidence notes

- The raw disassembly excerpts in this packet are verbatim objdump
  output for whole functions (plus int3 padding to the next FDE
  where padding exists; the 0x514e900 getter is immediately
  followed by the next FDE at 0x514e994, so its excerpt carries no
  padding), produced by `export_excerpts.py --binary
  work/hl-node-94.bin`. Instruction text such as `endbr64` in
  those excerpts is genuine instruction text present in the target
  binary, not a placeholder.
- The packet JSON (`records.json`) carries semantic records only —
  function ranges with SHA-256, sentinel cells, call sites, branch
  targets and censuses. Instruction-level detail lives only in the
  raw excerpt text files.
- `verify.py` re-derives every record from the binary: the target
  digest, the carve SHAs, the padding, the lookup call targets,
  the sentinel rip-relative resolutions, the null-lookup jump
  targets, the indirect dispatch call encodings, the FDE records
  and the censuses, plus the packet manifest hashes.
