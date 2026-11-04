# RE-001-node115-lu-fallback-inner: the fallback's inner route and gate

- Component ID: RE-001-node115-lu-fallback-inner
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `8fd8db6` (unmoved by
  fetch before analysis)
- Claim status: observation for all byte-backed claims; inference is
  marked where it appears (none load-bearing); unresolved items are
  listed in README.md
- Scope included and excluded: included — inner route `0x635fb50`
  end to end, fallback gate `0x6360610` completion (table-index
  math), tail-route call shapes, census of inner/fallback/tail-route/
  workers. Excluded — full decodes of workers `0x63c19a0` /
  `0x63c1930`, tail route `0x635f4b0`, method pointees, drain helper,
  field-drop callees, #200 delegates, unwind callee.

## Reproduce

Worktree `~/workspace/hl-wt-calls206-115`, branch
`codex/re-004-calls206-115`, from origin/main `8fd8db6`. Static
analysis only; the node binary was never executed.

- `objdump -d --start-address=0x635fb50 --stop-address=0x635fcf2
  artifacts/node/115/hl-node` — inner route full dump.
- `objdump -d --start-address=0x6360610 --stop-address=0x63606ca
  artifacts/node/115/hl-node` — fallback full dump.
- `readelf --debug-dump=frames artifacts/node/115/hl-node` — FDE
  bounds: inner `0x635fb50..0x635fcf2` (1058B), fallback
  `0x6360610..0x63606ca` (186B), tail route `0x635f4b0..0x635f697`
  (423B), workerA `0x63c19a0..0x63c1af4` (340B), workerB
  `0x63c1930..0x63c199d` (109B).
- Whole-`.text` census: byte scan for E8/E9 rel32 and rip-relative
  LEA over `.text` (VA `0x1419300`, file offset `0x1418300`, size
  `0x4fd7700`), plus `.rela.dyn` RELATIVE-addend scan for GOT.
  Two independent scan implementations agreed exactly (a per-byte
  loop and a `bytes.find` loop), and every found site was checked
  by disassembly.
- `python3 tools/node115_lu_fallback_inner.py` — exit 0.
- `python3 tests/test_node115_lu_fallback_inner.py` — 8/8 pass.

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000;
`.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is.
`.bss` spans `0x64ffe40..0x6728d24`, so `0x6711aa0`, `0x6711aa8`,
and `0x6711ab8` are all runtime-populated `.bss` addresses; only
their addresses and the indexing formulas are claimed.

### Inner route `0x635fb50` (exhibits: inner_head, inner_branch, inner_call)

- `inner_head.hex` (`0x635fb50..0x635fb90`, 64B, 20 strict):
  prologue pushes r15/r14/r13/r12/rbp/rbx, `sub $0x18,%rsp`;
  `cmpb $0x0,0x50(%rsp)` at `0x635fb6d` tests the 7th stack
  argument; `jne 0x635fc30` selects the branch path. Main path:
  `lea 0x40(%rdx),%rdi` (C+0x40 mutex), `mov %r9d,%r14d`,
  trylock call at `0x635fb83` → `0x63f17b0`; nonzero → `0x635fcc0`
  (flag C+0x68 = 1, return 1).
- Owner-count dance (both paths, same bytes): `addq $0x1,0x38(%r15)`
  at `0x635fb90`/`0x635fc44`; `cmp 0x30(%r15),%rbx`; if different,
  `addq $0x1,0x28(%r15)` and `mov %rbx,0x30(%r15)`.
- Branch path (`inner_branch.hex`, `0x635fc30..0x635fc76`, 70B, 17
  strict): trylock at `0x635fc37`; on failure call lock-wait
  `0x63bf680` at `0x635fce3`, set flag = 1, rejoin at `0x635fc44`;
  then `lea 0x29b0(%rbp),%rsi`, `mov $0x1,%r9d` at `0x635fc68`,
  call workerB `0x63c1930` at `0x635fc71`; flag clear at
  `0x635fc79`, unlock, return 0.
- Main path, mode computation (`inner_call.hex`,
  `0x635fbad..0x635fbe5`, 56B, 13 strict): if 6th argument nonzero,
  `0x635fc88` sets r9d = 0 and jumps to `0x635fbc5`; else `lea
  0x6711ab8`, `mov $0x2,%r9d`, `movzbl (%rax),%edx`,
  `sub %edx,%r9d` (mode = 2 − bss byte), save the `.bss` address
  at `0x8(%rsp)`; `lea 0x29b0(%rbp),%rsi`; call workerA `0x63c19a0`
  at `0x635fbd8`; `test %al,%al`; zero → `0x635fca0` (flag clear,
  unlock, dead `.bss` re-read load, epilogue `xor eax,eax` →
  return 0); nonzero → `mov 0x6e8(%r15),%r12` at `0x635fbe5`,
  flag clear, unlock, re-read `.bss` byte; if nonzero AND 6th
  argument zero, call tail route `0x635f4b0(thread, seg, C,
  [C+0x6e8])` at `0x635fc19`; return 0.
- The inner route never dereferences seg+0x29b0 itself: the only
  uses are the two `lea 0x29b0(%rbp),%rsi` sites feeding arg2 to
  the workers.
- FDE starts without `endbr64`: inner starts `41 57` (push r15),
  tail route starts `41 57 41 56` (push r15, push r14); fallback
  starts `f3 0f 1e fa`. The verifier asserts actual bytes.

### Fallback gate `0x6360610` (exhibits: gate_cont, gate_tail)

- #205's `fallback_gate.hex` covered `0x6360610..0x636063a`
  (gate load [seg+0x10f40] at `0x6360620`, zero → cold path
  `0x63606a0`; `.bss` byte `0x6711ab8` load at `0x636062c`, zero
  → return-nothing at `0x636066f`). Confirmed by re-read.
- `gate_cont.hex` (`0x636063a..0x636066f`, 53B, 12 strict + 1
  byte-continuation line): `mov 0x13450(%rbx),%eax` (segment
  counter); `lea 0x6711aa8,%rsi` (divisor address);
  `xor %edx,%edx`; `lea 0x6711aa0,%r9` (table-base address);
  `divq (%rsi)` (idx = counter % divisor); `lea
  (%rdx,%rdx,2),%rdi` (= 3*idx); `lea (%rdx,%rdi,4),%r8` (=
  13*idx); `shl $0x4,%r8` (= 208*idx); `add (%r9),%r8`
  (table base + 208*idx); `movzbl 0xac(%r8),%r10d`; nonzero →
  `0x6360680`, zero → fall through to return-nothing.
- `gate_tail.hex` (`0x6360680..0x636069a`, 26B, 8 strict):
  `lea 0x10ec8(%rbx),%rdx`, `mov %rbx,%rsi`, `xor %ecx,%ecx`,
  `mov %rbp,%rdi`, pops, `jmp 0x635f4b0` at `0x6360695`.
- Cold path `0x63606a0` (cited, not exhibited): `mov
  0x11cc0(%rsi),%rcx`, `xor %r9d,%r9d`, `lea 0x10ec8(%rsi),%rdx`,
  `push $0x1`, `lea 0x29e8(%rsi),%r8`, call inner at `0x63606be`,
  pops, `jmp 0x636062c` (re-check from the `.bss` byte, not from
  the gate load — inner runs at most once per invocation).

### Census (all sites disassembly-verified as real calls)

- Inner `0x635fb50`: E8 `0x63606be` (fallback), `0x6361009` (FDE
  `0x6360ed0..0x636116d`), `0x6361258` (FDE
  `0x6361170..0x63612a6`); 0 E9, 0 LEA, 0 GOT.
  - Caller `0x6361009` setup: `push %r10` at `0x6360ff1` after
    `movzbl %bpl,%r10d` (stack7 = runtime byte); rdx =
    seg+0x115c0, rcx = [seg+0x11cc0]+0x18, r8 = seg+0x75d8,
    r9d = r12b.
  - Caller `0x6361258` setup: `mov $0x1,%r9d` at `0x6361231`,
    `push $0x0` at `0x6361244` (stack7 = 0); same C/rcx/r8 shape.
- Fallback `0x6360610`: 12 E8, 0/0/0 — `0x63607fe` (FDE
  `0x63606d0`), `0x636130e` (push-small), `0x6361806` /
  `0x636183e` / `0x6361886` (FDE `0x6361320`), `0x63628a5` (FDE
  `0x6362190`), `0x6363acc` (page-owning free), `0x6364e3e`
  (FDE `0x6364880`), `0x63bccb6` (FDE `0x63bcb80`), `0x63bd526`
  (FDE `0x63bd2e0`), `0x63bd6ae` (push-large), `0x63bd816`
  (page sink). (thread, seg) convention spot-checked at
  `0x6361806` (rdi=rbx, rsi=r15) and `0x63607fe` (rdi=r14,
  rsi=r12) plus #205's two push-wrapper sites.
- Tail route `0x635f4b0`: E8 `0x635fc19` (inner), `0x6361129`
  (FDE `0x6360ed0`); E9 `0x6360695` (fallback gate); 0 LEA, 0 GOT.
- WorkerA `0x63c19a0`: E8 `0x635fbd8` (inner), `0x6360f7c` (FDE
  `0x6360ed0`), `0x63611ef` (FDE `0x6361170`), `0x63c1bfc`
  (FDE `0x63c1b00`); 0/0/0.
- WorkerB `0x63c1930`: E8 `0x635fc71` (inner branch),
  `0x63610a4` (FDE `0x6360ed0`); 0/0/0.

### Disjointness

All five exhibits are disjoint from #202–#205 exhibits (checked
in the verifier against the full prior-range list). `gate_cont`
starts exactly at `0x636063a`, where #205's `fallback_gate.hex`
ends — adjacent, not overlapping.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in
this packet; it is an evidence packet only.

## Results and limitations

- Verifier exit 0 (5 excerpts, 39 key-byte sites, census 23 E8 +
  1 E9 sites, MANIFEST 15/15).
- Unit tests 8/8 pass.
- `make doctor`: analysis_ready true. `make verify`: exit 0.
  `make catalogue-check`: exit 0. `make test`: 77 files attempted,
  1 failed — the pre-existing test_node115_catalogue Errno 18
  cross-device-link error; this packet's file [36/77] passes 8/8.
- Limitations: worker/tail-route internals undecoded; `.bss`
  values unknown; table entry layout beyond stride/byte unknown;
  FDEs `0x6360ed0` / `0x6361170` unidentified; fallback arg
  convention verified by spot check, not exhaustively, for all 12
  sites.
- Next question: decode tail route `0x635f4b0` end to end (see
  README.md).
