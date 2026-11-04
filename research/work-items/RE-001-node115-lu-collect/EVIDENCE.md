# RE-001-node115-lu-collect: the node #115 lu collect sibling

- Component ID: lu allocator-adjacent ctx state machine, collect (removal) side
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (fetch-confirmed unmoved
  before analysis)
- Claim status: observation for all decoded paths, counts, and census;
  inference for the counter semantics (stated as observed pairings);
  unresolved for the table population, the `+0x10 == 1` meaning, the
  second caller FDE, the remove helper internals, the finalizer
  internals, and the output array allocation site
- Scope included and excluded: included is exactly the FDE
  `0x6363560..0x636365a` (250 bytes) plus census of its callers and
  its one callee by address. Excluded: the feeder FDE, the second
  caller FDE, the remove helper body, the finalizer body, and all
  bytes claimed by packets #183–#221 (cited by address only).

## Reproduce

From the repository root, with the pinned node artifact materialized
(`artifacts/node/115/hl-node`, SHA-256 above):

```sh
python3 tools/node115_lu_collect.py
python3 -m unittest tests.test_node115_lu_collect -v
make doctor verify test catalogue-check
(cd research/work-items/RE-001-node115-lu-collect && sha256sum -c MANIFEST.sha256)
```

Static byte reads and disassembly only. No execution of the node
binary at any point. Coordinate system: `.text` file offset =
VA − 0x1000; `.data.rel.ro` / `.got` = VA − 0x2000; `.rodata` =
VA as-is. FDE bounds from `readelf --debug-dump=frames-interp`.
Callers from a whole-`.text` E8 rel32 scan; GOT absence from a
`.rela.dyn` addend scan (60,723 entries).

## Evidence

- Entry `0x6363560`: `endbr64`, `push %rbx`, `mov %rcx, %rbx`.
  rdi is never read before being overwritten as the call argument.
- Head check `0x6363568`: `cmp 0xc0(%rcx), %rdx`, `je 0x6363620`;
  head-clear block writes `[ctx+0xc0] = 0` and decrements
  `[ctx+0xb0]`, with no `+0xa8` write anywhere in the FDE.
- Table select `0x6363575`: `shr $0x14`, `movzbl %al`, 40-byte
  stride (`lea (%rcx,%rcx,4)` then `lea (%r8,%rdi,8)` from base
  `0x6711b40`), `cmpl $0x1, 0x10(%r9)`, `je 0x63635c0`.
- Slot-remove `0x6363595`: `lea 0xc8(%rbx), %rdi`,
  `call 0x63acb40` at `0x636359f` (rel32 verified), then
  `[ctx+0xb8]--` and `[ctx+0xb0]--`.
- Gate `0x63635c0`: `lea 0x650969c`, `cmp %r11d, 0x13450(%rsi)`,
  `jb 0x63635ac` (unsigned skip); anchor compare
  `cmp 0xd8(%rbx), %rdx`, `je 0x6363638`.
- Rotation `0x63635dc..0x636360c`: twelve 4-byte moves, in the order
  documented in README.md; `[item+0x28]` never written.
- Anchor `0x6363638`: `[item+0x28]` self-link test, clear-or-advance
  of `[ctx+0xd8]`, then rotation or shared tail.
- Raw disassembly and byte exhibits are kept beside this record as
  `cs_*.hex` / `cs_*.objdump.txt`; strict mnemonic counts exclude
  objdump byte-continuation lines.
- Analysis is complete over the FDE: every branch target was resolved
  and every exit path enumerated (five paths, three `ret` sites).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in
this packet. Comparison against #220 is observational: same ctx
layout, same gate, same anchor rule, related-but-different rotation
backlinks (see README.md). No source text is copied or used as a
correctness oracle.

## Results and limitations

- Verifier exit 0; unit tests 10/10; `make verify`, `make
  catalogue-check` exit 0; `make test` 77 files attempted with only
  the pre-existing catalogue Errno 18 failure (see README.md).
- Machine-readable metrics: 5 excerpts, 206 bytes, 48 strict
  mnemonics, 6 incoming E8, 1 outgoing E8, 0 GOT, 250-byte FDE.
- Remaining gaps are listed under "Unresolved" in README.md.
- No progress gate beyond the packet's own checks is requested.
- Next question: decode the slot-remove helper `0x63acb40` end to
  end (see README.md).
