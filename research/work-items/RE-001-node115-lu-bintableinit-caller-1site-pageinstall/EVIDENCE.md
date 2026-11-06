# RE-001-node115-lu-bintableinit-caller-1site-pageinstall: single-site page-range install caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-pageinstall
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly + byte exhibits); entry `rsi` caller-side meaning unresolved; composed field value semantics beyond the write site unresolved
- Scope included and excluded: included — the single FDE `0x63ae6e0..0x63ae974` only. Excluded — bin_table_init body `0x63d9880..0x63d9a64` (#262), lu-miss handler `0x63d9700..0x63d987b` (#215), neighboring FDEs.

## Reproduce

Worktree `~/workspace/hl-wt-calls305-115` on upstream main `05bc2de30`, branch `codex/re-004-calls305-115`. Static analysis only; the node binary is never executed.

- `objdump -d --start-address=0x63ae6e0 --stop-address=0x63ae974 artifacts/node/115/hl-node` (exhibit `bintableinit_caller_pageinstall_1site.objdump.txt`)
- Raw window bytes: `bintableinit_caller_pageinstall_1site.hex` (660 raw binary bytes, not hex text)
- Verifier: `python3 tools/node115_lu_bintableinit_caller_pageinstall_1site.py` (exit 0, 100 checks)
- Unit tests: `python3 tests/test_node115_lu_bintableinit_caller_pageinstall_1site.py` (exit 0, 12 checks; tamper controls first)
- `make verify` (exit 0, 560 evidence-packet manifests, 7164 entries)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue: README.md`, also on a pristine checkout)

## Evidence

Coordinate system: VA = file offset + 0x1000 for `.text`. FDE bounds from an own `.eh_frame` parse (135,313 FDEs, sorted before bisect; PC-relative sdata4, fixed 4-byte range fields). Previous FDE `0x63ae2b0..0x63ae6d1` (packet #304, gap 15 bytes all `0xcc`); next FDE `0x63ae980..0x63aed39` (padding 12 bytes all `0xcc`).

Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1a8,%rsp`, canary at `0x198(%rsp)` (loaded at `0x63ae70d`, checked at `0x63ae7c4..0x63ae7d5`, failure jumps to `0x63ae8f7` which calls `__stack_chk_fail` at `0x63f0d70`).

Entry registers: `rdi` = context (kept in `r15`), `rsi` = live input (saved to `0x8(%rsp)` before the bti call and the lu-miss call, restored after each; passed to the lu-miss handler; caller-side meaning not established), `rdx` = struct pointer (kept in `rbp`), `ecx` = value low bits (kept in `rbx`).

Walk: `lea 0x1b0(%rdi),%r14` at `0x63ae6eb` (context table). The page cursor `rbx` steps `0x1000` per page from `page(0x8(%rbp)) + 0x1000` up to `page(0x8(%rbp)) + page(0x10(%rbp)) - 0x2000` (end `r13` = `r12 + rax - 0x2000` at `0x63ae749`; loop exits via `jb 0x63ae7c4` at `0x63ae764` and `jae 0x63ae770` at `0x63ae7c2`). The loop head compares the cursor against the base page (`cmp %rbx,%r12` at `0x63ae770`) and tests the cursor's low bits (`test $0x3fffffff,%ebx` at `0x63ae775`, `jne 0x63ae7b0` — direct store path; never taken for a `0x1000`-aligned cursor). Per page: top index `(cursor >> 0x1a) & 0xf0` (`shr $0x1a,%r11` at `0x63ae783`, `and $0xf0,%r11d` at `0x63ae78e`, `add %r14,%r11` at `0x63ae795`), high bits `cursor & 0xffffffffc0000000` (`and` at `0x63ae787`), top entry compared at `0x63ae79b` (`cmp %rdi,%rcx`, mismatch to the scan at `0x63ae7f0`), second level `(cursor >> 0x9) & 0x1ffff8 + table + 0x8` (`shr $0x9,%rax` at `0x63ae7a3`, `and $0x1ffff8,%eax` at `0x63ae7a7`, `add 0x8(%r11),%rax` at `0x63ae7ac`). On a match the composed value in `rbp` is stored (`add $0x1000,%rbx` at `0x63ae7b0`, `add $0x8,%rax` at `0x63ae7b7`, `mov %rbp,-0x8(%rax)` at `0x63ae7bb`).

Composed value: `rbp = (ecx << 0x30) | (struct pointer & 0xffffffffffff) | 1` — `shl $0x30,%rbx` at `0x63ae728`, `movabs $0xffffffffffff,%rdx` at `0x63ae72c`, `and %rdx,%rbp` at `0x63ae736`, `or $0x1,%rbp` at `0x63ae751`. No `shl/sar $0x10` + mask transform, no node-resolution tables (`0x65096c0`/`0x6511780`), no size tables (`0x6727a00`/`0x67277c0`) anywhere in this FDE.

Bin_table_init site: block `0x63ae830` entered only by the null-context `je` from `0x63ae71a` (`test %rdi,%rdi` at `0x63ae717`); `lea 0x10(%rsp),%r14` at `0x63ae830`, `mov %rsi,0x8(%rsp)` at `0x63ae835`, `mov %r14,%rdi` at `0x63ae83a`, call at `0x63ae83d` (`e8 3e b0 02 00` -> `0x63d9880`), `mov 0x8(%rsp),%rsi` at `0x63ae842`, rejoin `jmp 0x63ae720` at `0x63ae847`. The preceding instruction is `xchg %ax,%ax` at `0x63ae82e` (2-byte nop).

Scan: single 8-slot move-to-front scan, table+`0x100` in `r14`. Slot compares: slot 0 `0x63ae7f7` (`cmp %r8,%rcx`), slot 1 `0x63ae85b` (`cmp %r10,%rcx`), slot 2 `0x63ae8ac` (`cmp %r8,%rcx`), slot 3 `0x63ae8d3` (`cmp %rdx,%rcx`), slot 4 `0x63ae8df` (`cmp %r8,%rcx`), slot 5 `0x63ae90e` (`cmp %r10,%rcx`), slot 6 `0x63ae91e` (`cmp %r8,%rcx`), slot 7 `0x63ae941` (`cmp 0x170(%r14),%rcx`). Slots 0–6 load the slot value into a register first; slot 7 compares memory directly. All are normal-operand order (slot value first, key second); no key-first reversed-operand compare. Slot-0 hit uses the inline block at `0x63ae7fc..0x63ae82c` (rejoin `jmp 0x63ae7b0`); slots 1–7 share the move-to-front block at `0x63ae860` (`r9d` = previous slot index, `eax` = slot index, shift `*16`, swap slot into head; rejoin `jmp 0x63ae815`). Exhaustion falls to the lu-miss block at `0x63ae94e` (`xor %r9d,%r9d`; `mov $0x1,%r8d`; `mov %rbx,%rcx`; `mov %r14,%rdx`; `mov %r15,%rdi`; `mov %rsi,0x8(%rsp)`), call at `0x63ae965` to `0x63d9700`, `mov 0x8(%rsp),%rsi` at `0x63ae96a`, rejoin `jmp 0x63ae7b0` at `0x63ae96f`.

Calls: 3 (bin_table_init `0x63ae83d`, lu-miss `0x63ae965`, `__stack_chk_fail` `0x63ae8f7`). Exit: single `ret` at `0x63ae7ec`; all 22 jump instructions target inside the window — no tail-jump exit. `eax` = 0 on the plain path (`xor %eax,%eax` at `0x63ae715` and `0x63ae755`); the move-to-front reuses `eax` as a slot index, so `eax` at `ret` reflects the last slot index when a scan hit occurred.

Census (from the objdump exhibit): 151 strict lines, 3 calls, 1 ret, 0 bsr, 0 lock, 22 jumps (0 outside window). Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9880`, grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17; this FDE holds 1 raw site. `.rela.dyn`: 60,723 total, 59,534 RELATIVE; `.rela.plt`: 278 entries, counted separately.

Disjointness: range-only collector over the merged tree plus all prior `hl-wt-calls*` worktree records (exhibits/windows only; all range-bearing forms; decimal-integer start/end accepted; plain `int(x, 16)` for hex strings; 0 skipped). Verifier scanned 61,384 priors, 0 skipped, NONE (deduplicated figure 60,606 after removing 778 within-file duplicate ranges).

## Implementation and comparison

Not yet implemented — this packet is evidence only (static verifier + unit tests). No Rust reconstruction is claimed for this window.

## Results and limitations

- Verified: FDE bounds, exhibit bytes, strict/call census, site-block shape, page-range install loop, single 8-slot scan, canary, jump closure, rel32 targets, rela counts, raw-e8 tiers, disjointness over every exhibit range, slug uniqueness, MANIFEST — verifier exit 0 (100 checks), unit tests exit 0 (12 checks), `make verify` exit 0.
- Not covered: bin_table_init body and lu-miss handler (cited, not claimed); the entry `rsi` value's caller-side meaning; the composed field value's semantics beyond the write site; neighboring FDEs.
- Next question: packet #306 decodes `0x63ae980..0x63aed39` (953 bytes, 1 bin_table_init site, 2 lu-miss sites, 1 ret, 0 bsr — the next surviving 1-raw candidate, verified by program against all prior exhibits).
