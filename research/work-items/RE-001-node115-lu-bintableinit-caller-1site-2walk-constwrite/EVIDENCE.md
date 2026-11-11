# RE-001-node115-lu-bintableinit-caller-1site-2walk-constwrite: single-site two-walk const-write caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-2walk-constwrite
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly + byte exhibits); entry `rsi` caller-side meaning unresolved; no return value claimed; constant value semantics beyond the write sites unresolved
- Scope included and excluded: included — the single FDE `0x63ae980..0x63aed39` only. Excluded — bin_table_init body `0x63d9880..0x63d9a64` (#262), lu-miss handler `0x63d9700..0x63d987b` (#215), neighboring FDEs.

## Reproduce

Worktree `~/workspace/hl-wt-calls306-115` on upstream main `05bc2de30`, branch `codex/re-004-calls306-115`. Static analysis only; the node binary is never executed.

- `objdump -d --start-address=0x63ae980 --stop-address=0x63aed39 artifacts/node/115/hl-node` (exhibit `bintableinit_caller_2walk_constwrite_1site.objdump.txt`)
- Raw window bytes: `bintableinit_caller_2walk_constwrite_1site.hex` (953 raw binary bytes, not hex text)
- Verifier: `python3 tools/node115_lu_bintableinit_caller_2walk_constwrite_1site.py` (exit 0, 109 checks)
- Unit tests: `python3 tests/test_node115_lu_bintableinit_caller_2walk_constwrite_1site.py` (exit 0, 12 checks; tamper controls first)
- `make verify` (exit 0, 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue: README.md`, also on a pristine checkout)

## Evidence

Coordinate system: VA = file offset + 0x1000 for `.text`. FDE bounds from an own `.eh_frame` parse (135,313 FDEs, sorted before bisect; PC-relative sdata4, fixed 4-byte range fields). Previous FDE `0x63ae6e0..0x63ae974` (packet #305, gap 12 bytes all `0xcc`); next FDE `0x63aed40..0x63aefdb` (padding 7 bytes all `0xcc`).

Frame: `endbr64`, pushes r14/r13/r12/rbp/rbx, `sub $0x190,%rsp`, canary at `0x188(%rsp)` (loaded at `0x63ae9ac`, checked at `0x63aea5f..0x63aea70`, failure jumps to `0x63aed34` which calls `__stack_chk_fail` at `0x63f0d70`).

Entry registers: `rdi` = context (kept in `rbx`), `rsi` = live input (kept in callee-saved `r13` across the bti call and both lu-miss calls; passed to the lu-miss handler; caller-side meaning not established), `rdx` = struct pointer (kept in `rbp`), `ecx`/`r8d` unused in this FDE.

Phase-1 walk: `lea 0x1b0(%rdi),%r12` at `0x63ae98d` (context table). Key is `0x8(%rbp)` (loaded at `0x63ae9bf`). Top index `(key >> 0x1a) & 0xf0` (`shr $0x1a,%rax` at `0x63ae9c9`, `and $0xf0,%eax` at `0x63ae9cd`, `add %r12,%rax` at `0x63ae9e0`), high bits `key & 0xffffffffc0000000` (`and` at `0x63ae9d2`), page `key & 0xfffffffffffff000` (`and` at `0x63ae9d9`). The top-level entry is compared at `0x63ae9e6` (`cmp %rsi,%rdx`); a mismatch falls to scan A at `0x63aeaa0`. On a match, the second level `(key >> 0x9) & 0x1ffff8 + table + 0x8` (`shr $0x9,%r14` at `0x63ae9f2`, `and $0x1ffff8,%r14d` at `0x63ae9f6`, `add 0x8(%rax),%r14` at `0x63ae9fd`) resolves into `r14`.

Second walk (derived key): `rdx = page(0x10(%rbp)) + page(0x8(%rbp)) - 0x1000` (`mov 0x10(%rbp),%rbp` at `0x63aea01`, `and $0xfffffffffffff000,%rbp` at `0x63aea05`, `lea -0x1000(%rcx,%rbp,1),%rcx` at `0x63aea0c`): top index `(rdx >> 0x1a) & 0xf0`, high bits `rdx & 0xffffffffc0000000`, second level `(rdx >> 0x9) & 0x1ffff8 + table + 0x8` (`shr $0x9,%rcx` at `0x63aea3a`, `and $0x1ffff8,%eax` at `0x63aea41`, `add 0x8(%rsi),%rax` at `0x63aea46`). The top-level entry is compared at `0x63aea31` (`cmp %rdi,%r11`); a mismatch falls to scan B at `0x63aeae8`.

Constant write: `movabs $0xe8000000000000,%rcx` at `0x63aea4a`; `mov %rcx,(%r14)` at `0x63aea54` (first-walk target); `test %rax,%rax` at `0x63aea57` guards the second store (`je 0x63aea5f` skips it when the second-level value is null); `mov %rcx,(%rax)` at `0x63aea5c` (second-walk target). There is NO `shl/sar $0x10` + mask transform (like #303, #304 and #305, unlike #298–#302), no node-resolution tables (`0x65096c0`/`0x6511780`), and no size tables (`0x6727a00`/`0x67277c0`) anywhere in this FDE. Entry `ecx`/`r8d` are not used — the written value is a constant, not composed from the entry registers.

Bin_table_init site: block `0x63aea90` entered only by the null-context `je` at `0x63ae9b9` (`test %rdi,%rdi` at `0x63ae9b6`); `mov %rsp,%r12` at `0x63aea90`, `mov %r12,%rdi` at `0x63aea93`, call at `0x63aea96` (`e8 e5 ad 02 00` -> `0x63d9880`), rejoin `jmp 0x63ae9bf` at `0x63aea9b`. No `rsi` save/restore — `rsi` lives in callee-saved `r13` across the call. The preceding instruction is `cs nopw 0x0(%rax,%rax,1)` at `0x63aea86`.

Scan A: 8-slot move-to-front scan, table+`0x100` in `r12`, key high bits in `rdx`. Slot compares: slot 0 `0x63aeaa0` (`cmp 0x100(%r12),%rdx`), slot 1 `0x63aeb35` (`cmp 0x110(%r12),%rdx`), slot 2 `0x63aec00` (`cmp %rdx,0x120(%r12)`), slot 3 `0x63aec13` (`cmp %rdx,0x130(%r12)`), slot 4 `0x63aec26` (`cmp %rdx,0x140(%r12)`), slot 5 `0x63aec39` (`cmp %rdx,0x150(%r12)`), slot 6 `0x63aec4c` (`cmp %rdx,0x160(%r12)`), slot 7 `0x63aec5a` (`cmp 0x170(%r12),%rdx`). Slots 0, 1, 7 are normal-operand compares (memory first, key second); slots 2–6 are reversed-operand compares (key first, memory second) — five reversed compares, the most in the 1-raw chain so far (#301 had exactly one; #300, #302–#305 had none). Slot-0 hit uses the inline block at `0x63aeaae..0x63aece` (rejoin `jmp 0x63aea01` into the derived-key recompute); slots 1–7 share the move-to-front block at `0x63aeb43` (`edi` = slot index, shift `*16`, swap slot into head; rejoin `jmp 0x63aeaca`, which continues through the slot-0 tail to `jmp 0x63aea01`). Exhaustion falls to the lu-miss A block at `0x63aec70` (`xor %r9d,%r9d`; `mov $0x1,%r8d`; `mov %r12,%rdx`; `mov %r13,%rsi`; `mov %rbx,%rdi`), call at `0x63aec82` to `0x63d9700`; the return value goes to `r14` (`mov %rax,%r14` at `0x63aec8b`), then `mov 0x8(%rbp),%rcx` / page mask, rejoin `jmp 0x63aea01` at `0x63aec95`.

Scan B: 8-slot move-to-front scan, same table, key high bits in `r11`. Slot compares: slot 0 `0x63aeae8` (`cmp 0x100(%r12),%r11`), slot 1 `0x63aeb9e` (`cmp 0x110(%r12),%r11`), slot 2 `0x63aeca0` (`cmp 0x120(%r12),%r11`), slot 3 `0x63aecb4` (`cmp 0x130(%r12),%r11`), slot 4 `0x63aecc8` (`cmp 0x140(%r12),%r11`), slot 5 `0x63aecdc` (`cmp %r11,0x150(%r12)`), slot 6 `0x63aecf0` (`cmp %r11,0x160(%r12)`), slot 7 `0x63aecfe` (`cmp 0x170(%r12),%r11`). Slots 0–4, 7 are normal-operand; slots 5–6 are reversed-operand. Slot-0 hit uses the inline block at `0x63aeaf6..0x63aeb28` (rejoin `jmp 0x63aea4a` into the constant-write block); slots 1–7 share the move-to-front block at `0x63aebac` (`r8d` = slot index, shift `*16`, swap slot into head; rejoin `jmp 0x63aeb12`, which continues through the slot-0 tail to `jmp 0x63aea4a`). Exhaustion falls to the lu-miss B block at `0x63aed18` (`xor %r9d,%r9d`; `mov $0x1,%r8d`; `mov %r12,%rdx`; `mov %r13,%rsi`; `mov %rbx,%rdi`), call at `0x63aed2a` to `0x63d9700`; the return value is used directly as the second-level pointer, rejoin `jmp 0x63aea4a` at `0x63aed2f`.

Calls: 4 (bin_table_init `0x63aea96`, lu-miss `0x63aec82` and `0x63aed2a`, `__stack_chk_fail` `0x63aed34`). Exit: single `ret` at `0x63aea85`; all 30 jump instructions target inside the window — no tail-jump exit. No return value is claimed: `eax` is not set as a return value on the `ret` path (it holds the second-level index `(derived key >> 0x9) & 0x1ffff8` from address computation at `0x63aea41`); the observable effects are the two stores.

Census (from the objdump exhibit): 189 strict lines, 4 calls, 1 ret, 0 bsr, 0 lock, 30 jumps (0 outside window). Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9880`, grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17; this FDE holds 1 raw site. `.rela.dyn`: 60,723 total, 59,534 RELATIVE; `.rela.plt`: 278 entries, counted separately.

Disjointness: range-only collector over the merged tree plus all prior `hl-wt-calls*` worktree records (exhibits/windows only; all range-bearing forms; decimal-integer start/end accepted; plain `int(x, 16)` for hex strings; 0 skipped). Verifier scanned 62,226 priors, 0 skipped, NONE (deduplicated figure 61,438 after removing 788 within-file duplicate ranges).

Survey correction: the #298–#305 surveys listed the next candidate `0x63aed40..0x63aefdb` with 2 lu-miss sites. A targeted objdump census of that FDE finds one call to `0x63d9700` (`0x63aefcd`); the other calls are bin_table_init `0x63aeea1` and `__stack_chk_fail` `0x63aef60` (3 calls total, 149 strict, 1 ret at `0x63aedb5`, 0 bsr). All other fall-through candidates were re-verified by program and match the survey exactly (`0x63aefe0` miss 2, `0x63af460` miss 4, `0x63afc60` miss 4, `0x63bc490` miss 1, `0x63bc730` miss 1, `0x63c2f00` miss 1 with bsr 1).

## Implementation and comparison

Not yet implemented — this packet is evidence only (static verifier + unit tests). No Rust reconstruction is claimed for this window.

## Results and limitations

- Verified: FDE bounds, exhibit bytes, strict/call census, site-block shape, two-phase walk, constant write to both resolved node fields, two 8-slot scans with per-scan reversed-operand tracking, canary, jump closure, rel32 targets, rela counts, raw-e8 tiers, disjointness over every exhibit range, slug uniqueness, MANIFEST — verifier exit 0 (109 checks), unit tests exit 0 (12 checks), `make verify` exit 0.
- Not covered: bin_table_init body and lu-miss handler (cited, not claimed); the entry `rsi` value's caller-side meaning; the constant value's semantics beyond the write sites; neighboring FDEs.
- Next question: packet #307 decodes `0x63aed40..0x63aefdb` (667 bytes, 1 bin_table_init site, 1 lu-miss site — corrected from 2 — 1 ret, 0 bsr — the next surviving 1-raw candidate, verified by program against all prior exhibits).
