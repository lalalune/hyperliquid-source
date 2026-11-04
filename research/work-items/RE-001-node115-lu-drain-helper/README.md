# RE-001-node115-lu-drain-helper

## Question

Packet #207 asked: decode the drain helper `0x63697a0` end to end —
what does it do with (entry, buffer-or-NULL), and what does the
entry+0xb8 accumulator count?

## Answer (short)

The drain is a conditional condvar signal, not a data move. It
takes (entry, buffer-or-NULL) and signals the condition variable
at entry+8 in exactly two cases: buffer is NULL (unconditional),
or buffer is non-NULL and its first qword exceeds 99,999,999
(`0x5f5e0ff`, unsigned). Otherwise it returns silently and touches
nothing. The entry+0xb8 accumulator counts weighted arg4 units:
each contributing tail-route pass adds arg4 scaled by a
sigmoid-like factor of q = stackbuf[0] / *(C-0x80) — 0 at q = 0,
~arg4 at q = 199, exactly arg4 for q > 199 — and the tail route
fires the drain (and resets +0xb8 to 0) when +0xb8 exceeds 0x400.

## Targets

- Drain: FDE `0x63697a0..0x63697d2` (50B, 15 strict instrs).
- Accumulator core: `0x63a9712..0x63a9742` (48B, 12 strict) inside
  FDE `0x63a96f0..0x63a974a` (90B).
- Load stub: FDE `0x63bfb90..0x63bfb98` (8B, 3 strict):
  `mov (%rdi),%rax; ret` — the drain's only helper.

## The drain, end to end

Signature: `(entry, buffer)` = (rdi, rsi). `drain.hex` is the
whole FDE.

1. `test %rsi,%rsi; je 0x63697bd` — NULL buffer skips the
   compare entirely and goes straight to the signal path.
2. Non-NULL: `call 0x63bfb90(buffer)` loads rax = *(buffer)
   (`stub.hex`); `cmp $0x5f5e0ff,%rax; jbe 0x63697d0` —
   unsigned below-or-equal returns silently (`pop %rbx; ret`).
   Only *(buffer) > 99,999,999 falls through.
3. Signal path: `lea 0x8(%rbx),%rdi; jmp pthread_cond_signal@plt`
   (`0x63f1800`, JUMP_SLOT reloc at `0x64ee850` confirmed).
   So entry+8 is a pthread condition variable. The drain touches
   no other entry field, writes nothing, and has no return
   contract in effect: the signal path returns the PLT value,
   the silent path returns the loaded qword, and both known
   callers discard eax.

The two gates are separate: entry+0xb8 > 0x400 gates the drain
CALL (in the tail route), while *(buffer) > 99,999,999 gates
the SIGNAL (inside the drain). A drain call does not always
signal.

## The entry+0xb8 accumulator

The tail route (see #207) reaches the accumulator only when its
C-sequence produced a positive difference: stackbuf[0] is set to
*(entry+0xb0), compared against *(C+0x88) by `0x63bfc00`
(sign compare), and — only when greater — reduced by
`0x63bfc40` to stackbuf[0] = *(entry+0xb0) - *(C+0x88).
That same stackbuf is then passed to the accumulator and, on
the threshold path, to the drain.

Accumulator `0x63a96f0(C, stackbuf, arg4)` (`accum.hex` is the
div-to-scale core; prologue loads are address-cited):

- D = *(C-0x80) (arg1 minus 0x80, loaded via `0x63bfb90`);
  N = *(stackbuf) (also via `0x63bfb90`).
- q = N / D, unsigned (`div %rbp`; no divisor-zero guard in
  the FDE — observation only, no fault claim).
- q > 199 (`cmp $0xc7; ja`) → return arg4 unchanged.
- Else return arg4 * (2^24 - table[199-q]) >> 24, where table
  is 200 qwords at `.rodata` `0xb9e140`, monotonically
  increasing from 20 to exactly 2^24 (verifier-checked).
  The factor is 0 at q = 0, ~0.49 near q = 100, ~1 at q = 199,
  and saturates at 1 for q >= 199.

The tail route adds that return to entry+0xb8 on every pass
with arg4 != 0 (gate calls pass arg4 = 0 and skip the
accumulation but still run the threshold check). When
entry+0xb8 > 0x400 (1024), the tail resets it to 0 and calls
drain(entry, stackbuf) — so the drain's buffer at that point
holds the same difference N that fed q.

So +0xb8 counts weighted arg4 units, not raw entries, bytes,
or calls: each pass contributes arg4 scaled by weight(q).
What arg4 itself measures is unresolved ([C+0x6e8] from the
inner route, a forwarded caller argument from FDE `0x6360ed0`
— #207), as is the enclosing struct behind *(C-0x80) and any
semantic label for N/D beyond the difference-over-base ratio.
The 10^8-1 drain threshold's unit is likewise unresolved.

## Census (whole `.text`, byte scan + per-site disassembly check; `.rela.dyn` for GOT)

- Drain `0x63697a0`: 2 direct E8, 0 E9, 0 LEA, 0 GOT — both in
  the tail route: `0x635f632` (threshold path, buffer =
  stackbuf) and `0x635f645` (predicate path, buffer = NULL
  via `xor %esi,%esi`). No other caller exists.
- Accumulator `0x63a96f0`: 1 direct E8 (`0x635f681`, tail
  route arg4 branch), 0/0/0.
- Predicate `0x6369790`: 1 direct E8 (`0x635f526`, tail
  route), 0/0/0 — context only; its body (entry+0xa8 == 1)
  is #207's characterisation, not re-claimed here.
- Load stub `0x63bfb90`: 60 direct E8, 0/0/0 — a generic
  qword-load helper used across the binary, not drain-private.

## Corrections to earlier packets

- **#207 completed.** Its drain and accumulator were
  "characterised only"; both are now decoded end to end. Its
  two drain call sites are confirmed exactly (`0x635f632`
  stackbuf, `0x635f645` NULL), as is the threshold-path
  stackbuf identity (same buffer feeds accumulator and drain).
- **#207 refined.** The drain's signal is conditional on
  *(buffer), not on entry+0xb8: the +0xb8 > 0x400 check gates
  the drain call, the *(buffer) > 99,999,999 check gates the
  signal inside it. #207's guard list, slot arithmetic, and
  call-site census are otherwise confirmed.
- No other earlier packet is corrected.

## Unresolved (stated, not inferred)

- The enclosing struct behind *(C-0x80) (the accumulator's
  divisor source) and the semantic labels of N, D, and arg4.
- The unit of the drain threshold 99,999,999 (10^8 - 1).
- Who waits on the entry+8 condition variable (waiters are
  outside the drain's census; only the signal side is decoded).
- All `.bss` contents; the table's provenance beyond its
  monotone 20 → 2^24 shape.
- The predicate byte +0xa8 vs drain-trigger byte +0xac
  semantics beyond #207's gating description.

## Next question

Decode the inner route's two workers `0x63c19a0` / `0x63c1930`
end to end: what do modes 0, 1, and 2 - bss byte select, and
what do they do with the seg+0x29b0 reference passed through
untouched by the inner route? Behind it, still open: the
C-0x80 divisor source, the entry+8 condvar waiters, the two
runtime method pointees ([seg+0x29d0] / [seg+0x11cf0] writers),
the drain helper `0x51e8720`, the field-drop callees
`0x5a50a10` / `0x5a4d200`, and #200's delegates `0x51f3e20` /
`0x57ec1b0` and unwind callee `0x1680cab`.
