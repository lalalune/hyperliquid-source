# RE-001-node115-lu-slotclaim: the slot-claim helper

- Component ID: RE-001-node115-lu-slotclaim
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation (entry/exit contract, splice mechanics,
  census); unresolved (chain invariant, multi-node selection rule,
  `+0x0`/`+0x10` word roles, non-allocator caller purposes)
- Scope included and excluded: included — the `0x63ac480` helper end to
  end as far as its contract and splice mechanics; excluded — the
  remainder helper `0x6369fe0`, the fresh helper `0x636a140`, the
  allocator worker internals beyond its scan/call/carve interface, and
  the five non-allocator callers' purposes.

## Reproduce

Worktree `~/workspace/hl-wt-calls217-115`, local branch
`codex/re-004-calls217-115`, from `origin/main` of
`~/workspace/hyperliquid-source` (main clone HEAD untouched at
`2993e46`). Static analysis only; the node binary was never executed.

```
objdump -d --start-address=0x63ac480 --stop-address=0x63acb33 \
  artifacts/node/115/hl-node
objdump --dwarf=frames artifacts/node/115/hl-node | grep 63ac480
python3 tools/node115_lu_slotclaim.py
python3 tests/test_node115_lu_slotclaim.py
```

Coordinate system: file offset = VA − 0x1000 for `.text`
(verified: bytes at file offset `0x63ab480` are `f30f1efa`, the
`endbr64` at VA `0x63ac480`).

## Evidence

FDE `0x63ac480..0x63acb33` (435B, via `objdump --dwarf=frames`).
Two `ret` sites: `0x63ac947` (shared exit) and `0x63acb22` (NULL early
return). Zero `call` instructions in the FDE (verified by grep over
the full disassembly): the helper is pure inline splice code.

Entry (`sc_entry`): `endbr64; mov (%rdi),%rdx; test %rdx,%rdx;
je 0x63acb20; lea 0x28(%rdx),%r10; push r15; mov %rdi,%r11;
push r14; push r13; push r12; push rbp; push rbx`.

Slot clear (`sc_clear`): `mov 0x8(%r10),%rcx` (`rcx = [node+0x30]`);
`movq $0,0x8(%rdi)` (`[slot+8] = 0`); `test %rcx,%rcx;
je 0x63ac990` (single-node/alternate-link path).

Key comparison (`sc_cmp`): `cmp %rbx,%rbp; setb %sil;
cmp %rbp,%rbx; sbb $0,%esi; test %esi,%esi; jne 0x63ac52f` — the
`setb`/`sbb` signum idiom over the two-word key (`+0x20` first,
`+0x8` tiebreak), yielding -1, 0, or +1. A -1 result takes the
insert-before splice branch at `0x63acaf0`; any other result takes
the append/rotate branch at `0x63ac52f`.

Splice (`sc_splice`): `mov 0x10(%r8),%rbx` (`rbx = [r14+0x38]`);
`movq %r14,%xmm2; movq %rbx,%xmm5; punpcklqdq %xmm5,%xmm2;
movups %xmm2,(%r9)` (`[rcx+0x28] = (r14, [r14+0x38])`);
`test %rbx,%rbx; je 0x63ac557; mov %rcx,0x28(%rbx)`
(`[[r14+0x38]+0x28] = rcx` when nonzero).

Shared exit (`sc_exit`): `mov %rdx,(%r11)` (`[slot] = remainder`);
`mov %rcx,%rax` (return detached block); six pops; `ret`.

Key-byte sites checked, not excerpted: NULL return `31c0` at
`0x63acb20`; main ret `c3` at `0x63ac947`; pair zero `0f114228`
(`movups %xmm0,0x28(%rdx)`) at `0x63ac4c2`; single-node alternate-link
follow `498b4210` at `0x63ac990`; chain walk load `488b4730` at
`0x63ac5b6`; scan slot setup `4889ef` at `0x636a78f`; scan call
`e8e91c0400` at `0x636a792`.

Single-node case traced exactly: `[slot] = N`, `[N+0x30] = 0`,
`[N+0x38] = 0` → entry clears `[slot+8]`, `rcx = 0` jumps to
`0x63ac990`, `rax = [N+0x38] = 0`, `rcx = N`, `rdx = 0`, `rax = 0`
jumps to the shared exit, `[slot] = 0`, return `N`.

Census (whole-`.text` byte scan + per-site disassembly; `.rela.dyn`
60,723 entries for GOT): 20 direct E8, 0 E9, 0 LEA, 0 GOT. Allocator
worker FDE `0x636a680..0x636aad8`: 15 sites (`0x636a792`,
`0x636a7a7`, `0x636a7bc`, `0x636a7d1`, `0x636a7e6`, `0x636a7fb`,
`0x636a81a`, `0x636a82c`, `0x636a83e`, `0x636a850`, `0x636a862`,
`0x636a874`, `0x636a886`, `0x636a898`, `0x636aa33`). Other FDEs:
`0x6361320..0x63620da` (2 sites), `0x6362190..0x6362901` (1 site),
`0x6364880..0x6365142` (2 sites). Allocator scan interface verified:
`mov %rbp,%rdi` at `0x636a78f`, `call 0x63ac480` at `0x636a792`,
`test %rax,%rax; jne 0x636a97e` (carve), `rbp` stepping `0x10` per
slot at `0x636a7a0`.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed in
this packet; it is an evidence packet only.

## Results and limitations

Verified: entry/exit contract, slot-clear and remainder-store
behavior, key comparison idiom, splice mechanics, detach hygiene
(`+0x28` pair zeroing, `+0x30` clearing), zero-call property, census
(20 E8 / 0 E9 / 0 LEA / 0 GOT), FDE bounds, MANIFEST 15/15.

Unknown: the exact invariant of the slot's chain; which node of a
multi-node chain is selected; the `+0x0`/`+0x10` word roles; the five
non-allocator callers' purposes; what populates a fresh slot's chain.

Next question: decode the `0x6369fe0` remainder helper end to end:
what it does with `(pool, block, aligned, aligned, requested)`, how it
re-inserts the remainder into the free list, and when it leaves the
remainder out.
