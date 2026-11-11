# RE-001 — power-of-ten divisibility gate (0x593da30, #115)

## Bounded question

Routine 0x593da30 (FDE 0x593da30..0x593db22, 242 bytes) takes an
out pointer in rdi, an unsigned 64-bit value in rsi, an unsigned
64-bit index in rdx and a context pointer in rcx. What exactly
does it check, in what order, what does it write on each outcome,
and what are its exits?

## Established answer

The routine is a divisibility gate: it answers whether `value`
is exactly divisible by the power of ten that the selected table
record's class byte prescribes, writing a two-case tagged result
into the out slot. The decision runs in this order:

1. **Index check.** If `index >= [ctx+0x10]` (the entry count),
   it leaves through the noreturn indirect call at 0x593db1c
   through slot 0x64df620, RELATIVE-resolved to 0x1680cbf, with
   rdi = index, rsi = count and rdx = 0x6476678 (a static whose
   contents are not interpreted). Nothing is written.
2. **Bound check.** It reads the element
   `E = [[ctx+0x08] + index*32]` (32-byte array stride; only the
   lane's first 8 bytes are read). If `E >= [ctx+0x28]` (the
   bound), it leaves through the noreturn indirect call at
   0x593db06 through slot 0x64df830, RELATIVE-resolved to
   0x1680c10, with rdi = 0x64768d8 (a static whose contents are
   not interpreted); this path sets no other argument register.
   Nothing is written.
3. **Class byte.** It reads the single byte
   `T = byte [[ctx+0x20] + E*0x158 + 0x48]` (0x158-byte record
   stride; no other record byte is read). If `T >= 9`, it
   writes the tag word 0x6a at (out) and returns, without
   writing the payload qword at (out)+8.
4. **Divisibility test.** For T in 0..8 the divisor is
   `d = 10^(8 - T)` (T=8 → 1, T=7 → 10, …, T=0 → 10^8),
   assembled by a multiply ladder over the bits of 8 − T
   (×10 for bit 0, ×100 for bit 1, ×10000 for bit 2, ×10^8 for
   the T == 0 remainder arm). The routine divides with a 32-bit
   `div` when `(value | d)` fits in 32 bits and a 64-bit `div`
   otherwise; both paths compute the exact quotient and
   remainder. If `value mod d == 0` it writes the quotient at
   (out)+8 and then the tag word 0x1a2 at (out); otherwise it
   writes only the tag word 0x6a at (out).

Both return paths return rdi in rax. The routine writes nothing
besides the tag word and, on the divisible path, the payload
qword — never the out bytes +0x02..+0x08 or any byte past
+0x10 — and nothing at all on the two exit paths. It has no
direct calls and no tail jumps; the two slot calls above are
its only transfers out, and both are on failed checks. Two
control-flow details of the ladder, both confirmed by the
instruction trace and consistent with the Unicorn differential
below: the block at 0x593dac2..0x593dac6 (test the class byte;
jump to the 0x6a write if it is nonzero; jump to the ×10^8
multiply otherwise) is unreachable for every class byte — the
ladder states that could arrive there (8 − T in {1, 2, 3})
all leave through the earlier `je` exits, and 8 − T == 0
never enters the ladder — and the ×10^8 multiply at 0x593daf3
is reached only by falling through the compare at 0x593daee
when 8 − T == 8, that is, exactly for T == 0.

## What it reads

| Offset | Width | Role |
|---|---|---|
| ctx+0x10 | 8 | entry count; the index is compared against it first |
| ctx+0x08 | 8 | element array base pointer |
| array+index*32 | 8 | the element E (only this u64 of the lane) |
| ctx+0x28 | 8 | bound; E must be strictly below it |
| ctx+0x20 | 8 | record table base pointer |
| record+E*0x158+0x48 | 1 | class byte T selecting the divisor |

## Consumers

- 0x517b04f (in 0x517af50..0x517b75d) and 0x517c13f (in
  0x517c040..0x517c84d): identical two-stage chains — the
  caller first calls 0x593d7e0 with the same out slot
  (rsp+0x30), index and context, checks that stage's tag
  against 0x1a2 and copies its payload, and only then calls
  this routine with the same out slot, rsi = r15, rdx = rbp
  (the same index) and rcx = r13+0x90 (the same context). This
  packet claims only the sites, the FDE ranges and this
  argument setup; the first-stage routine is not its subject.
- 0x57c9cd2 (in 0x57c9c70..0x57c9f5d): rdi is a caller stack
  temporary (rsp+0x10), rcx is r8+0x10; rsi and rdx are set
  earlier in the caller.
- 0x57ca5d4 (in 0x57ca550..0x57caa3a) and 0x57caac4 (in
  0x57caa40..0x57caf2a): identical setup — rdi = rsp+0x20,
  rsi = the u64 field at the caller's input +0x40, rdx = the
  u64 field at the caller's input +0x38, rcx = rbx+0x90.

## What is NOT claimed

- Names or meanings for the context, the element array, the
  record table or the class byte beyond the offsets and the
  selection behaviour above; in particular, what quantity
  `value` is, what the records describe, and why these
  divisors.
- The bodies or behaviour of the two exit callees at 0x1680cbf
  and 0x1680c10; only the slots, their RELATIVE-resolved
  targets and the argument registers this routine sets are
  pinned.
- The contents or meaning of the two statics at 0x6476678 and
  0x64768d8 passed on the exit paths.
- The semantics of the tag words 0x1a2 and 0x6a beyond this
  routine's own writes and the one caller-side comparison
  against 0x1a2 recorded above.
- The first-stage routine 0x593d7e0 called by two of the
  consumers before this gate.
- Native execution, whole-program equivalence or byte identity
  with any reconstructed implementation.

## Evidence in this packet

- `main.txt` — byte-verified disassembly of the routine
  (0x593da30..0x593db22), regenerated from the work binary.
- `frames.txt` — readelf FDE lines for the routine and its five
  callers.
- `relocations.txt` — empty: no relocation line in the dump
  names the routine (checked by verify.py).
- `callers.tsv` — the five direct call sites with their
  enclosing FDE ranges; no tail jumps, no stored qwords.
- `records.json` — the machine-readable form of the answer
  above, including the divisor table and the census.
- `export_excerpts.py`, `census.py` — regenerators for the
  excerpt and the census.
- `differential.py` — the Unicorn differential below.
- `verify.py` — the packet checker (next section).

The Python model is `tools/pow10_divisibility_gate_da30_115.py`
with tests in `tests/test_pow10_divisibility_gate_da30_115.py`
(119 checks).

## Reproduce

```sh
python3 research/work-items/RE-001-pow10-divisibility-gate-da30-115/export_excerpts.py
python3 research/work-items/RE-001-pow10-divisibility-gate-da30-115/census.py
python3 research/work-items/RE-001-pow10-divisibility-gate-da30-115/verify.py
python3 tests/test_pow10_divisibility_gate_da30_115.py
```

`verify.py` re-checks, against the digest-verified work binary:
the artifact digest against `provenance/artifacts.json`; the
packet manifest; excerpt regeneration byte-for-byte; every
excerpt instruction byte-for-byte against the raw binary (with
objdump's split long instructions accumulated); spot
instructions against a fresh objdump run and the raw binary;
the FDE ranges against a fresh frame dump; the empty
relocation set against a fresh relocation dump; census
consistency (callers.tsv against a fresh scan) including the
two internal indirect calls and the absence of internal direct
calls and tail jumps; the callers.tsv caller functions as the
smallest enclosing FDE ranges from a fresh frame dump; the
semantic records; and the model tests. In the worktree where
this packet was authored it prints `ALL CHECKS PASSED`; the
same run was repeated in a clean `git archive` copy of the
commit with the binary materialized at `work/hl-node-115.bin`.

Verification scope beyond verify.py, stated honestly:
`differential.py` emulates the routine's real bytes under
Unicorn (the two call slots' contents replaced by recording
stub addresses — the slots are data the routine reads, which
is what lets the noreturn exits be observed) and compares tag,
payload, untouched out bytes, rax and both exits' argument
registers against the model over 9,597 cases: every class byte
0..255 against 14 directed values, 6,000 seeded random cases,
and the index/bound edge cases. It reports `TOTAL: 9597 cases,
0 failures`. verify.py deliberately does not run the
differential or the census regeneration beyond comparing
callers.tsv to one fresh census run — the differential needs
the `unicorn` package, which is not part of the repository's
own toolchain.
