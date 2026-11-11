# RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp-3exit: fourth 2-raw bin_table_init caller

- Component ID: lu bin_table_init caller FDE 0x63c89c0..0x63c8d5a (node #115 lookup chain)
- Target release and full SHA-256: artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (static disassembly only; the target binary is never executed)
- Scope included and excluded: included — the single FDE 0x63c89c0..0x63c8d5a, its two bin_table_init sites, two lu-miss fallbacks, three tail-jump exits, and both 8-slot scans. Excluded — bin_table_init body 0x63d9880..0x63d9a64 (#262), lu-miss handler 0x63d9700..0x63d987b (#215), tail-jump target bodies, neighboring FDEs (previous 0x63c8820..0x63c89b7, next 0x63c8d60..0x63c94fc which is packet #281's window), runtime values of any .bss byte.

## Reproduce

Working directory: the worktree root. Tool versions: system objdump/readelf, python3.
Static commands only (no execution of the target):

- `objdump -d --start-address=0x63c89c0 --stop-address=0x63c8d5a artifacts/node/115/hl-node` (exhibit .objdump.txt; 201 strict lines)
- `readelf --debug-dump=frames artifacts/node/115/hl-node` (FDE list; 135,313 FDEs; this window at 0x63c89c0..0x63c8d5a)
- `python3 tools/node115_lu_bintableinit_caller_walk_rsp_3exit_2sites.py` (static verifier; byte reads only)
- `python3 tests/test_node115_lu_bintableinit_caller_walk_rsp_3exit_2sites.py` (unit tests; tamper controls first)

Declared execution/side effects: none. The target binary is only read.

## Evidence

Coordinate system: VA addresses as shown by objdump. .text file offset = VA - 0x1000; .rodata = VA as-is; .data = VA - 0x3000. .bss has no file content; only mechanisms are reported, never runtime values.

Validated boundaries: .eh_frame bounds by own parse (PC-relative sdata4, fixed 4-byte range fields, CIE pointer relative to the CIE_id field, FDE list sorted before bisect; 135,313 FDEs total, cross-checked against readelf). Previous FDE 0x63c8820..0x63c89b7 (gap 9 bytes, all 0xcc); next FDE 0x63c8d60..0x63c94fc (padding 6 bytes, all 0xcc). The next FDE is packet #281's window, adjacent, not overlapping.

Raw disassembly: see bintableinit_caller_walk_rsp_3exit_2sites.objdump.txt (full targeted dump) and bintableinit_caller_walk_rsp_3exit_2sites.hex (raw binary bytes, not hex text).

Callers/callees: 5 calls — 2 bin_table_init (0x63c8a6e, 0x63c8c16, both plain %rsp), 2 lu-miss (0x63c8ca9, 0x63c8d50), 1 __stack_chk_fail (0x63c8d28). Exits: 3 canary-checked tail jumps (0x63637f0, 0x63bd6c0, 0x6363260); 0 ret. Exit-ness verified per FDE: the same trio were tail-jump exits in #288's FDE but ordinary returning calls in #287's FDE.

Analysis was complete for this window (whole FDE decoded); neighboring FDEs were not decoded.

## Implementation and comparison

Independent Rust path: not yet implemented/measured. No source reconstruction is claimed; this packet is evidence only (addresses, counts, branch shapes, scan structure), validated by the static verifier's recounts and by regeneration comparisons in the unit tests (hex + objdump regeneration, tamper controls).

## Results and limitations

Metrics (denominators explicit): strict mnemonic lines 201/201 recounted; calls 5/5 (2 bti + 2 miss + 1 stack-chk-fail); bsr 0; lock sub 0; lock add 0; ret 0; tail jumps 3/3 verified as the only jumps leaving the window. Raw 0xe8 census: 108 total, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17; this FDE 2. .rela.dyn 60,723 total / 59,534 RELATIVE; .rela.plt 278 separately. Disjointness: NONE over prior ranges (verifier count, 0 skipped).

What remains unknown: the bodies of the tail-jump targets, the runtime values of any .bss byte, and the remaining 2-raw candidates plus the 1-raw tier (future packets).

Next question: build packet #292 on the next surviving 2-raw candidate 0x63cd910..0x63cddce (1214 bytes, 2 bin_table_init sites, 2 lu-miss sites, 1 ret, 1 bsr), after re-verifying its site count and claim status.
