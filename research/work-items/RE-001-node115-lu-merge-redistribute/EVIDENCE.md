# RE-001-node115-lu-merge-redistribute: merge and redistribute helpers

- Component ID: RE-001-node115-lu-merge-redistribute
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only)
- Claim status: observation
- Scope included and excluded: see README.md. The merge helper
  `0x4ca2500`, redistribute-left `0x4c93c20`, and
  redistribute-right `0x4c9b3b0` are claimed in full; the free
  wrapper, the resolver, and the leaf op's inline upward merge
  core are not.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Binary: `artifacts/node/115/hl-node` (105,896,032 bytes, SHA-256
above). Coordinate system: `.text` file offset = VA − 0x1000;
`.data.rel.ro`/`.got` file offset = VA − 0x2000; `.rodata` file
offset = VA. No execution: all analysis is static disassembly
(objdump) plus ELF relocation and `.eh_frame` parsing. Tool
versions: system objdump/readelf as installed in the VM; the
packet verifier is pure Python 3 stdlib.

```sh
objdump -d -M intel --start-address=0x4ca2500 --stop-address=0x4ca2915 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4c93c20 --stop-address=0x4c93f18 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4c9b3b0 --stop-address=0x4c9b6ff \
  artifacts/node/115/hl-node
python3 tools/node115_lu_merge_redistribute.py
python3 -m unittest tests.test_node115_lu_merge_redistribute -v
```

## Evidence

FDE extents are unwind-described ranges, confirmed against
`tools/fde_extents.py` output (merge `0x4ca2500..0x4ca2915`,
redistribute-left `0x4c93c20..0x4c93f18`, redistribute-right
`0x4c9b3b0..0x4c9b6ff`) and against the single `ret` in each
range. Instruction counts below are strict mnemonic-line counts
(raw objdump address lines also count multi-byte continuation
lines, which are not instructions; the packet verifier counts
the strict way).

- Merge: 1045 bytes; body proper to `ret` at `0x4ca28c9` =
  970 bytes, 213 instructions; tail = 75 bytes, 12
  instructions; 4 nops; CIE `00000000`. Body SHA-256 is in
  records.json; full FDE SHA-256 likewise.
- Redistribute-left: 760 bytes; body proper to `ret` at
  `0x4c93ecc` = 685 bytes, 149 instructions; tail = 75 bytes,
  12 instructions; 2 nops; CIE `00000000`.
- Redistribute-right: 847 bytes; body proper to `ret` at
  `0x4c9b6cc` = 797 bytes, 167 instructions; tail = 50 bytes,
  8 instructions; 2 nops; CIE `00000000`.

Key sites (full list pinned by the verifier):

- Merge entry: `r14 = [frame+0x18]` (left node),
  `r15 = [frame+0x28]` (right node), `r12 = [frame+0]`
  (parent), `rbx = [frame+0x10]` (separator index).
  Direction test at `0x4ca251d` (`cmp rdx,0x1`); merged-size
  test at `0x4ca254a` (`cmp r8,0xc`); separator key save at
  `0x4ca25a8`; parent key memmove at `0x4ca25d0` (GOT
  `0x64df568`); separator store at `0x4ca25da`; sibling key
  memcpy at `0x4ca2605` (GOT `0x64df508`); separator value
  store at `0x4ca264b`; sibling value memcpy at
  `0x4ca2674`; parent children memmove at `0x4ca269e`;
  parent-children reparent loops at `0x4ca26d0`
  (single-step) and `0x4ca2700` (unrolled-by-4); parent
  count decrement at `0x4ca276e`; kept-children memcpy at
  `0x4ca27ce`; kept-children reparent loops at `0x4ca27f0`
  (single-step) and `0x4ca2820` (unrolled-by-4); free at
  `0x4ca2892` (GOT `0x64df4a0`); output writes at
  `0x4ca28ab..0x4ca28b7`.
- Redistribute-left entry: `rbx = [frame+0x28]` (right/current
  node), `rbp = [frame+0x18]` (left/donor node); overflow
  test at `0x4c93c41` (`cmp rax,0xc`); underflow test at
  `0x4c93c5a` (`sub r12,rsi`, `jb`); right key memmove at
  `0x4c93c9d`; right value memmove at `0x4c93cb9`;
  donor-key memcpy at `0x4c93cff`; donor-value memcpy at
  `0x4c93d15`; separator swap at `0x4c93d18..0x4c93d75`;
  levels gate at `0x4c93d75..0x4c93d83`; right-children
  memmove at `0x4c93db8`; donor-children memcpy at
  `0x4c93dd0`; reparent loops at `0x4c93e20`
  (unrolled-by-4) and `0x4c93ea0` (single-step).
- Redistribute-right entry: `rbp = [frame+0x18]`
  (left/current node), `rbx = [frame+0x28]` (right/donor
  node); overflow test at `0x4c9b3ce` (`cmp rax,0xc`);
  underflow test at `0x4c9b3ea` (`sub r13,rsi`, `jb`);
  separator swap at `0x4c9b420..0x4c9b46e`; donor-key
  memcpy at `0x4c9b487`; donor-value memcpy at `0x4c9b4a2`;
  donor-key memmove at `0x4c9b4cd`; donor-value memmove at
  `0x4c9b4e3`; levels gate at `0x4c9b4e6..0x4c9b4f8`;
  donor-children memcpy at `0x4c9b520`; donor-children
  memmove at `0x4c9b540`; moved-children reparent switch
  at `0x4c9b546..0x4c9b5de` (5 children max); donor-remaining
  reparent loops at `0x4c9b620` (unrolled-by-4) and
  `0x4c9b6a0` (single-step).

Caller censuses (full-`.text` E8 byte scan + relocation
addends): merge 1 direct caller (`0x4d24967`), 0 GOT;
redistribute-left 3 direct callers (`0x4cbdbcb`,
`0x4d2497b`, `0x4d24f12`), 0 GOT; redistribute-right 2
direct callers (`0x4d249ac`, `0x4d24f2c`), 0 GOT.

Panic provenances (all file
`/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/alloc/src/collections/btree/node.rs`,
91 bytes at `0x4344f8`, resolved via Location structs and
`R_X86_64_RELATIVE` addends):

- Merge edge bound: `node.rs:1491:9`, message at `0x913599`
  (142 bytes), Location `0x649a648`.
- Merge merged size: `node.rs:1414:9`, message at `0x913627`
  (42 bytes), Location `0x649a660`.
- Merge / redistribute-left memcpy length:
  `node.rs:1876:5`, message at `0x913439` (40 bytes),
  Location `0x649a540`.
- Redistribute-left overflow: `node.rs:1537:13`, message at
  `0x9134e5` (51 bytes), Location `0x649a5b8`.
- Redistribute-left underflow: `node.rs:1538:13`, message
  at `0x913518` (39 bytes), Location `0x649a5d0`.
- Redistribute-left levels: `node.rs:1585:22`, message at
  `0x913496` (40 bytes), Location `0x649a5e8`.
- Redistribute-right overflow: `node.rs:1600:13`, message
  at `0x91353f` (50 bytes), Location `0x649a600`.
- Redistribute-right underflow: `node.rs:1601:13`, message
  at `0x913571` (40 bytes), Location `0x649a618`.
- Redistribute-right levels: `node.rs:1649:22`, message at
  `0x913496` (40 bytes), Location `0x649a630`.

Overlap checks: candidate directory absent from live upstream
main (trees API recursive, 720 entries, truncated=false;
contents API 404); open-PR searches for `merge-redistribute`,
`lu merge`, `redistribute`, `merge helper` return only the
inviting priors #2314 (#196) and #2328 (#197) plus unrelated
packets — no competitor claims these bytes. Claimed bodies
are disjoint from all #183–#197 claimed ranges (checked
against every prior lu packet's records.json); #196/#197
records cite these helper addresses only as explicitly
not-decoded references.

## Implementation and comparison

Not yet implemented: no Rust reconstruction of these helpers
is claimed. The packet is a static-evidence record with a
byte-exact verifier and corruption-controlled unit tests, per
the node-115 packet convention.

## Results and limitations

Verifier exit 0 (binary digest/size, FDE bytes and hashes,
body/tail splits, ret bytes, opcode spot checks, GOT
relocations, panic Locations and messages, packet hex and
records agreement, caller censuses). Packet unit tests 7/7.
`make doctor` analysis_ready true; `make verify` exit 0;
`make catalogue-check` exit 0; full `make test` with only
the single pre-existing test_node115_catalogue Errno 18
failure (cross-device link, fails identically on a pristine
checkout).

Limitations are listed in README.md, including the
redistribute-right 5-children reparent cap, the merge stale
tail-slot write, and the undecoded free wrapper. If
requesting no gate, say so: no progress gate is requested
beyond the packet's own verification.

Next question: the resolver `0x4d35b60` end to end — how it
consumes the leaf op's out48 (kept node, levels, edge index)
to swap the removed leaf key/value into the internal slot.
