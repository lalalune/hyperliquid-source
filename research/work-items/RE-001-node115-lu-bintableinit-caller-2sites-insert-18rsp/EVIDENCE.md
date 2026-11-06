# RE-001-node115-lu-bintableinit-caller-2sites-insert-18rsp: key-struct insert caller, 2 sites

- Component ID: RE-001-node115-lu-bintableinit-caller-2sites-insert-18rsp
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  105,896,032 bytes
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation for the window census, site blocks, branches,
  tables, and tail; inference for the node-insert reading of the tail;
  unresolved for all helper internals (including the key helper's
  null-return semantics)
- Scope included and excluded: FDE `0x63d4289..0x63d4425` only.
  bin_table_init body (#262), lu-miss handler (#215), all helper bodies,
  all tables and globals, and neighboring FDEs are cited/read, not claimed.

## Reproduce

Worktree `hl-wt-calls294-115` at upstream main
`05bc2de303c05525b71e7e257426e741bc66a390`. Static analysis only;
the binary was never executed. Targeted objdump:

```
objdump -d --start-address=0x63d4289 --stop-address=0x63d4425 \
  artifacts/node/115/hl-node
```

Verifier: `python3 tools/node115_lu_bintableinit_caller_insert_18rsp_2sites.py`
(exit 0). Unit tests:
`python3 tests/test_node115_lu_bintableinit_caller_insert_18rsp_2sites.py`
(exit 0). `make verify` exit 0 (559 manifests, 7159 entries).
`make catalogue-check` exit 2, pre-existing `Stale catalogue: README.md`
on the new base, also present on a pristine checkout. Full `make test`
not run (584 files; hours + VM-restart risk); deviation declared in
README/body.

## Evidence

Coordinates: VA; `.text` file offset = VA - 0x1000; `.rodata` VA as-is;
`.data` VA - 0x3000. FDE bounds from own `.eh_frame` parse (3 CIEs,
135,313 FDEs, list sorted before bisect; CIE code/data alignment and
return-address register precede the `z` augmentation data; sdata4 is
4 bytes): window `0x63d4289..0x63d4425` (412 bytes), prev FDE
`0x63d4171..0x63d4289` (packet #293's window, padding 0), next FDE
`0x63d4425..0x63d4497` (114 bytes, padding 0).

Raw disassembly in `bintableinit_caller_insert_18rsp_2sites.objdump.txt`
(102 strict mnemonic lines); raw bytes in
`bintableinit_caller_insert_18rsp_2sites.hex` (412 bytes, raw binary).
Callers/callees: 9 calls — size helper `0x63d3eee` at `0x63d42bc`,
size-class helper `0x63d3b3d` at `0x63d42e4`, key helper `0x6364880`
at `0x63d42f7`, bin_table_init at `0x63d431c` and `0x63d4358`
(rel32 to `0x63d9880`), phase-1 helper `0x63d3f0e` at `0x63d432a`,
phase-2 helper `0x63d4048` at `0x63d4369`, register helper
`0x63d39a0` at `0x63d43f4`, `__stack_chk_fail` at `0x63d4410`.
Single ret at `0x63d4424`; no tail jump leaves the window (both
unconditional jumps target inside). 1 `lock add` at `0x63d4387`
(`lock add %r14,0x38(%rax)`); 0 `lock sub`; 0 `bsr`; 0 lu-miss sites.

Tables read (not claimed): `0x67277c0` (size threshold, indexed by
size >> 3), `0x6727a00` (node resolution, indexed by phase-1 `eax`),
`0x65096c0` (index, keyed by value & 0xfff). Globals read (not
claimed): `0x6714738`, `0x6714730`, `0x67147c0`, `0x6714780`.
`0x6713606` gate byte not referenced. `.bss` has no file content;
no runtime values claimed. `.rela.dyn`: 60,723 total, 59,534
RELATIVE (readelf `-W`); `.rela.plt`: 278, counted separately.
Raw-e8 census: 108 total, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17;
this FDE 2 raw = 2 objdump sites.

Analysis was complete for this window; helper internals, the key
helper's null-return semantics, and the phase-1 helper's `eax`/`edx`
contract are unresolved by design.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included in
this packet. The packet is evidence only (README, EVIDENCE.md,
records.json, exhibits, MANIFEST.sha256) plus a static verifier and
unit tests with tamper controls (hex flip, strict-count change,
call-site change, injected partial overlap of a prior window — each
fails the temp-copy verifier; the clean temp copy passes).

## Results and limitations

Verifier exit 0, 91 checks, 0 failures; unit tests
exit 0, 12 checks, 0 failures; MANIFEST 5/5 OK;
git status exactly 3 paths (packet dir, tools file, tests file).
Disjointness: range-only collector over merged tree + prior worktree
records (exhibits/windows only, all range-bearing forms, decimal
start/end accepted, plain `int(x, 16)` for hex strings, 0 skipped) —
NONE for every exhibit range in this packet. What remains unknown:
helper internals, null-return semantics, and the 1-raw tier (17 FDEs)
after the 2-raw tier. Next question: packet #295 decodes
`0x63d4497..0x63d463e` (423 bytes, 2 bin_table_init sites, 0
lu-miss sites, 1 ret, 0 bsr).
