# RE-001-node115-lu-bintableinit-caller-2sites-walk-20rsp: fifth 2-raw bin_table_init caller

- Component ID: RE-001-node115-lu-bintableinit-caller-2sites-walk-20rsp
- Target release and full SHA-256: node 115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly + byte evidence); the helper's internal key computation is unresolved, not claimed
- Scope included and excluded: FDE `0x63cd910..0x63cddce` only. bin_table_init body, lu-miss handler body, helper `0x6364880` body, lazy-init `0x634ebb0` body, prev/next FDE bodies, and the four tables read are cited or read, not claimed.

## Reproduce

Working directory: the worktree root. Static analysis only; the binary is never executed.

```
objdump -d --start-address=0x63cd910 --stop-address=0x63cddce artifacts/node/115/hl-node
python3 tools/node115_lu_bintableinit_caller_walk_20rsp_2sites.py
python3 tests/test_node115_lu_bintableinit_caller_walk_20rsp_2sites.py
make verify
make catalogue-check
```

Tools: objdump (binutils), python3, readelf. The verifier recomputes the
`.eh_frame` bounds, the strict-line count, the call census, the rel32 call
targets, the site-block shapes, the canary check, the jump-exit closure, the
`.rela.dyn`/`.rela.plt` counts, the raw-e8 tiers, and the disjointness
against all prior packet exhibits. No execution, no side effects.

## Evidence

Coordinate system: virtual addresses as shown by objdump. File offsets:
`.text` = VA - 0x1000, `.rodata` = VA as-is, `.data` = VA - 0x3000.
`.bss` has no file content; only mechanisms are claimed, never values.

Validated boundaries: `.eh_frame` parse (CIE code/data/return-register
before `z` augmentation data; zPLR personality size map with sdata4 = 4
bytes; fixed 4-byte FDE range fields; CIE pointer relative to the CIE_id
field; FDE list sorted before bisect) gives window `0x63cd910..0x63cddce`,
prev `0x63ccd60..0x63cd907` (gap 9, all `cc`), next `0x63cddd0..0x63ce23b`
(padding 2, all `cc`). Raw exhibits: `bintableinit_caller_walk_20rsp_2sites.hex`
(raw binary bytes, 1214) and `.objdump.txt` (targeted objdump output).

Callers/callees: entry rdi = context (r12), rsi = string key (r13);
`strlen` 0x63cd951, helper 0x6364880 at 0x63cd9a3, lazy-init 0x634ebb0 at
0x63cdb71, bin_table_init 0x63cdaa8 and 0x63cdbdf, lu-miss 0x63cdd20 and
0x63cddba, `memcpy` 0x63cda67, `__stack_chk_fail` 0x63cddc9. Analysis is
complete over the window: all 258 strict lines are accounted for in the
README classification.

## Implementation and comparison

No implementation is claimed in this packet; it is an evidence packet only.
No Cargo graph, no build comparison, no fixture identity is asserted. The
verifier's regeneration comparison strips objdump output through the
`file format` line (the output starts with a blank line, then the path line)
and compares the disassembly body exactly.

## Results and limitations

Metrics with denominators: strict lines 258/258 classified; calls 9/9
accounted for; direct jumps 100% inside the window; disjointness NONE over
48,161 prior ranges with 0 skipped records; MANIFEST 5/5 digests.
`make verify` passes. `make catalogue-check` fails pre-existing on the new
base (`Stale catalogue: README.md`, also on a pristine checkout).

Unknown: the internal computation of helper 0x6364880's return value, and
the runtime contents of `.bss` and of the four tables read. The memcpy
target is described only as the resolved node pointer (rbp).

Next question: packet #293 decodes `0x63d4171..0x63d4289` (280 bytes,
2 bin_table_init sites, 0 lu-miss sites, 0 ret, 0 bsr).
