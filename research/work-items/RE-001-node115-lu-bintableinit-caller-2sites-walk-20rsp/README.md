# RE-001: lu bin_table_init 20rsp walk caller, 2 sites (node 115)

Fifth 2-raw caller FDE in the bin_table_init caller chain (after #288, #289,
#290, #291). The window is a string-keyed lookup/insert routine: it takes a
string key, computes the lookup key through helper 0x6364880, walks the
context table, and on a match copies the key string into the resolved node
after a refcount increment.

## Window

- FDE `0x63cd910..0x63cddce`, 1214 bytes, 258 strict lines, 9 calls, 1 ret.
- Prev FDE `0x63ccd60..0x63cd907` (gap 9, all `cc`), next FDE
  `0x63cddd0..0x63ce23b` (padding 2, all `cc`); adjacent, not overlapping.
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1b8,%rsp`,
  canary at `0x1a8(%rsp)`, single canary check at `0x63cda74`
  (`sub %fs:0x28,%rax; jne 0x63cddc9` -> `__stack_chk_fail` call at `0x63cddc9`).
- Entry: rdi = context (kept in r12), rsi = string key (kept in r13).
  `strlen` at `0x63cd951` (len in rbx, len+1 in r15). Null key or zero length
  returns 0 via `0x63cdb00` -> shared epilogue at `0x63cda6c`.
- The single ret is at `0x63cda97` (shared epilogue: `add $0x1b8,%rsp` +
  pops, return value = rbp). No tail jump leaves the window: every direct
  jump target lies inside `[0x63cd910, 0x63cddce)`.

## Key computation and size class

- Index table `0x65096c0` is read at `0x63cd96d` (`mov (%r14),%rsi`); if it
  is null, lazy-init callee `0x634ebb0` (packet #261's cited-only callee) is
  called at `0x63cdb71` with rdi=0, rdx=`lea 0x64da4b0`, and control rejoins
  at `0x63cd979`.
- Size gate: `cmp $0x1000,%r15` at `0x63cd979`, `ja 0x63cdb10`. Below the
  gate, threshold table `0x67277c0` is indexed by `(len+8)>>3` at `0x63cd995`.
  Above the gate, the size-class block at `0x63cdb10` computes the class
  with the FDE's only `bsr` at `0x63cdb3a`; a length above
  `0x7000000000000000` takes `0x63cdc94` (ecx = `0xe8`) and rejoins at
  `0x63cd99a`.
- Helper `0x6364880` is called at `0x63cd9a3` (rdi=context, rsi=key string,
  rdx=len+1, rcx=size class); its return value is kept in rbp and is the
  lookup key. A null return takes `0x63cdb00` and returns 0.
- The `0x6713606` gate byte seen in other walkers is NOT referenced here.

## bin_table_init sites (both `lea 0x20(%rsp)`, in-block)

- Site 1 at `0x63cdaa8`: block head `0x63cdaa0` (`lea 0x20(%rsp),%rbx;
  mov %rbx,%rdi`), reached by exactly one branch, `je 0x63cd9bf` on
  `test %r12,%r12` (null context) at `0x63cd9bc`. Rejoin: `mov %rbx,%rsi;
  jmp 0x63cd9c5` — the walk restarts with the stack-temp table.
- Site 2 at `0x63cdbdf`: block head `0x63cdbc8` (`mov %r11,0x18(%rsp);
  lea 0x20(%rsp),%r11; mov %r11,%rdi; mov %r8,0x10(%rsp);
  mov %r11,0x8(%rsp)`), reached by exactly one branch, `je 0x63cda19` on
  `test %r12,%r12` (null context) at `0x63cda16`. Rejoin: restores
  rdx/r11/r8, `jmp 0x63cda1f` — the second-level walk on the stack-temp
  table.
- Both sites pass the same stack temp `0x20(%rsp)`; neither lea is carried
  through a register from far away, so no register-trace argument is needed
  (contrast #289's `lea 0x60(%rsp),%r14` carried across two sites).

## Walk

- Table: context + `0x1b0` (`lea 0x1b0(%r12),%rsi` at `0x63cd9b4`).
- Top index: `(key >> 0x1a) & 0xf0`; second level:
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`.
- Phase 1: context-table walk at `0x63cd9c5`, then node resolution through
  table `0x6727a00` indexed by `(value >> 0x30)` at `0x63cda12`.
- Phase 2: top-slot re-check at `0x63cda1f`, second-level field extraction
  (`shl/sar $0x10`, mask `$0xffffffffffffff80` at `0x63cda41..0x63cda49`),
  index table `0x65096c0` indexed by `(value & 0xfff)` at `0x63cda55`,
  `lock add %r8,0x38(%r14)` at `0x63cda59` (refcount increment, not a
  decrement — the FDE has 0 `lock sub`), then
  `memcpy(rdi=rbp node, rsi=r13 key string, rdx=r15 len+1)` at `0x63cda67`,
  falling into the shared epilogue.

## Scans (8 slots each, 16-byte entries at table + `0x100`, move-to-front)

- Scan 1 (table rsi, first walk): slot 0 at `0x63cdab8`
  (`cmp 0x100(%rsi),%r11`), slot 1 at `0x63cdbfd` (`cmp 0x110(%rsi),%r11`),
  slots 2..7 unrolled at `0x63cdd2f..0x63cdd97` (reversed-operand compares
  at `0x140`, `0x150`, `0x160`). Slot-0 hit sequence at `0x63cdac5`;
  indexed move-to-front at `0x63cdc0a` (edi = slot index).
  Exhaustion -> lu-miss site `0x63cddba`.
- Scan 2 (table rdx, second walk): slot 0 at `0x63cdb80`
  (`cmp 0x100(%rdx),%r11`), slot 1 at `0x63cdc4b` (`cmp 0x110(%rdx),%r11`),
  slots 2..7 unrolled at `0x63cdc9e..0x63cdd00` (reversed-operand compares
  at `0x120`, `0x130`). Slot-0 hit sequence at `0x63cdb8d`;
  indexed move-to-front at `0x63cdc54` (r9d = slot index).
  Exhaustion -> lu-miss site `0x63cdd20`.

## lu-miss sites

- `0x63cdd20` (scan-2 exhaustion): rdi=r12 context, rsi=`lea 0x6511a00`,
  rdx=scan-2 table (rdx, unchanged), rcx=rbp key, r8=1, r9=0;
  rejoin `jmp 0x63cda3e` (second level).
- `0x63cddba` (scan-1 exhaustion): rdi=r12 context, rsi=`lea 0x6511a00`,
  rdx=scan-1 table (rsi moved to rdx at `0x63cdd9c`), rcx=rbp key, r8=1,
  r9=0; rejoin `jmp 0x63cd9fc` (second level).

## Call census

9 calls: bin_table_init x2, lu-miss x2, `strlen@plt` x1, helper `0x6364880`
x1, `memcpy@plt` x1, lazy-init `0x634ebb0` x1, `__stack_chk_fail@plt` x1.
1 ret, 1 bsr, 0 `lock sub`, 1 `lock add`.

## What is not covered

- The bodies of bin_table_init (`0x63d9880..0x63d9a64`, packet #262), the
  lu-miss handler (`0x63d9700..0x63d987b`, packet #215), helper `0x6364880`,
  and lazy-init callee `0x634ebb0` (packet #261, cited only) are cited, not
  claimed. The tables `0x6727a00`, `0x6511a00`, `0x67277c0`, `0x65096c0`
  are read, not claimed. Prev/next FDE bodies are not claimed.
- `.bss` has no file content; no claim is made about runtime values stored
  there. The helper's return value is described only as the lookup key; its
  internal computation is not decoded here.

## Verification

- Static verifier `tools/node115_lu_bintableinit_caller_walk_20rsp_2sites.py`
  exits 0 with 67 checks passing, 0 failing.
- Own unit tests `tests/test_node115_lu_bintableinit_caller_walk_20rsp_2sites.py`:
  10 checks pass, 0 fail, including tamper controls run against a temp
  copy's verifier
  (hex flip, strict-count change, call-site change, injected partial overlap
  of a prior window — each fails the temp verifier; the clean temp copy
  passes).
- `make verify` exit 0. `make catalogue-check` reports the pre-existing
  `Stale catalogue: README.md` failure on the new base (also present on a
  pristine checkout); it is not a regression from this packet.
- `MANIFEST.sha256 -c` passes (5 entries). `git status` shows exactly 3
  paths: the packet directory, the tools file, and the tests file.
- Disjointness: range-only collector over merged-tree + prior-worktree
  records (exhibits/windows only, decimal-integer start/end accepted, plain
  `int(x, 16)` for hex strings, 0 skipped) — NONE over 48,161 prior ranges
  for every exhibit range in this packet (the verifier scanned 48,162
  ranges including the packet's own window, self-excluded by exact match).
- Raw-e8 census: 108 total, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17; this
  FDE has 2 raw sites, matching its 2 objdump sites. Raw counts are an upper
  bound; site counts come from objdump mnemonics.
- `.rela.dyn`: 60,723 total / 59,534 RELATIVE; `.rela.plt` 278 entries,
  counted separately. DT_RELA/DT_JMPREL values were treated as VAs and mapped
  through PT_LOAD segments (readelf cross-checked).
- `.hex` exhibits are raw binary bytes, not hex text.
- Deviation from the repository's full `make verify test catalogue-check`
  gate: the full `make test` suite (584 files on the new base) is not run;
  it takes hours and risks a VM-restart interruption. Only the verifier, the
  packet's own tests, `make verify`, and the honest `make catalogue-check`
  report above are claimed.

## Next question

Packet #293 decodes `0x63d4171..0x63d4289` (280 bytes, 2 bin_table_init
sites, 0 lu-miss sites, 0 ret, 0 bsr — the next surviving 2-raw candidate
after this packet, verified by program against all prior exhibits; the
remaining 2-raw fall-through order is `0x63d4289..0x63d4425`,
`0x63d4497..0x63d463e`, `0x63d61a0..0x63d6575`, `0x63ed8b0..0x63edf05`).
