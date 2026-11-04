# RE-001-node115-lu-bintableinit-caller-4sites-walk-60rsp: bin_table_init caller walk, 4 sites, 60rsp temp

- Component ID: RE-001-node115
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390 (fetch-confirmed at build time)
- Claim status: observation (disassembly and byte census only; no runtime claims)
- Scope included and excluded: included: FDE 0x6365660..0x63673d9 only (7545 bytes). Excluded: bin_table_init body, lu-miss handler, neighbouring FDEs, all other call targets, runtime values.

## Reproduce

Working directory: repository root (worktree at 05bc2de30).
Static analysis only; the target binary is never executed.

- `objdump -d --start-address=0x6365660 --stop-address=0x63673d9 artifacts/node/115/hl-node`
- `python3 tools/node115_lu_bintableinit_caller_walk_60rsp_4sites.py` (exit 0)
- `python3 tests/test_node115_lu_bintableinit_caller_walk_60rsp_4sites.py` (exit 0)
- `make verify` (exit 0); `make catalogue-check` fails pre-existing on this base with "Stale catalogue: README.md" (also on a pristine checkout)
- `sha256sum -c research/work-items/RE-001-node115-lu-bintableinit-caller-4sites-walk-60rsp/MANIFEST.sha256` from the packet directory (MANIFEST paths are relative to the packet directory; tools/tests entries carry a ../../../ prefix)

## Evidence

Coordinate system: virtual addresses as shown by objdump; .text file offset = VA - 0x1000; .rodata VA as-is; .data VA - 0x3000. FDE bounds from .eh_frame (PC-relative sdata4, fixed 4-byte range fields, CIE pointer relative to the CIE_id field, rec+4).

- Window 0x6365660..0x63673d9, 7545 bytes, 1607 strict lines, 66 calls, 1 ret (0x63658e6), 10 bsr.
- Previous FDE 0x6365150..0x6365660 (gap 0); next FDE 0x63673e0..0x6367447 (padding 7 bytes 0xcc).
- Frame sub $0x1f8,%rsp, canary 0x1e8(%rsp); checks at 0x63658c3 and 0x63659ec to __stack_chk_fail call at 0x6366d8d.
- bin_table_init sites 0x63661c0, 0x63665e9, 0x63666c3, 0x6366dde (all rdi = lea 0x60(%rsp)); lu-miss sites 0x6366f6e, 0x636731f, 0x636739d, 0x63673cf (all rdi = (%rsp), rsi = lea 0x6511a00, rcx = rbp, r8 = 1, r9 = 0).
- Walk: (key >> 0x1a) & 0xf0 into context + 0x1b0; high bits key & 0xffffffffc0000000; second level (key >> 0x9) & 0x1ffff8 + table + 0x8; value resolved via 0x6727a00 indexed by (value >> 0x30); 0x65096c0 read by index only (no lock sub); (value >> 0x30) vs 0x23 gate.
- Scan: walk-table + 0x100, 16-byte entries, slot 0 MRU head; one unrolled scan (slots 2..7 at 0x120..0x170) and three indexed loops (index 1..8).
- Raw .hex exhibit beside this record is raw binary bytes, not hex text.
- Analysis was complete over the stated window only; no other range is claimed.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included in this packet. The verifier and tests are static byte/disassembly checks only.

## Results and limitations

- Verifier exit 0; unit tests exit 0 (tamper controls first, then clean temp copy, regeneration, independent recounts).
- Disjointness: NONE over prior records (range-only collector; census/cited-only subtrees excluded; self excluded by exact window equality).
- .rela.dyn: 60,723 total / 59,534 RELATIVE; .rela.plt: 278 entries (counted separately).
- Remaining gaps: the three remaining 4-raw caller FDEs, static leaves, named-only callee families.
- No full-scope gate is requested beyond the packet checks above; the full `make test` suite (584 files on this base) is not run by design (hours + VM-restart risk) and that deviation is stated in the PR body.
- Next question: packet #285 decodes 0x63d3080..0x63d379c (1820 bytes, 4 raw candidates).
