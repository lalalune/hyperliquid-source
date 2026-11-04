# RE-004: node115 signed interior bound arithmetic

Component: assets/fixed-point quantities, allocation only. Parent packet
RE-001-node115-notional-admission-clamp (PR2291) explicitly leaves this central
signed/multiply/clamp calculation unclosed. This packet studies that gap, not
its previously recorded lookup, predicate, baseline or outer quotient path.

Target: Linux x86-64 node115, 105896032 bytes, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `05bc2de303c05525b71e7e257426e741bc66a390`. New code independently authored
MIT; no unlicensed reference read/copied. ELF virtual addresses are unre-based.

## Original evidence frozen before new Rust

Full containing FDE `0x4483920..0x4483baa`: 650 bytes / 184 instructions,
with complete original FDE/CIE and agreeing GNU/Capstone exports. Only interior
spans `0x4483a08..0x4483a7a` and `0x4483ac5..0x4483b14` are interpreted.
Every other instruction is static context. The interior accepts six raw u64
words at R13; other registers/flags start unknown. Fields at hex offsets
0/8/10/18/20/28 are denoted M/A/B/C/D/Xbits. Read-only 48-byte fixture;
no calls, stores or spills allowed. Normal observation is RBX before4483b14;
N denotes arrival before4483b65, not a native return/error/panic result.

6452 distinct rows, including 37 diagnostic-frontier rows, freeze the original
instruction results. All59 selected instruction starts are visited. Eight
actual byte COW controls distinguish denominator guard, inner minimum, final
maximum, product ceiling, sign base, multiply overflow, diagnostic frontier
and multiplier field. Raw capture SHA is verified before/after; never modified.
Complete input/output streams are regenerated from native.py; FREEZE.json pins
their digests; target-smoke.tsv preserves representative raw original rows.

## Observed integer relation and limits

For X>0 use base=A, opposite=B, den=D; otherwise base=B, opposite=A, den=C.
Take unsigned magnitude of signed X, including MIN ->2^63. Multiply it by M
as u128. Denominator guard compares wrapping(den-1) with opposite; continuation
implies den>0. Divide opposite by den using the native 32/64-bit shortcut.
Multiplication overflow or product>2^63-2 retains base. Only after these guards
does the negative-magnitude frontier occur. MIN is not unconditionally N.
Reject borrows subtracting twice magnitude from den and twice product from
opposite. Multiply the quotient by remaining den; overflow or >2^63-2 retains
base. Otherwise the observed result is max(base,min(remaining opposite,product)).
These are byte-backed arithmetic observations, not economic units or row types.
The initial prose hypothesis of a final minimum was contradicted by the first
original probe and corrected before this freeze and before new Rust.

No whole containing function ABI, caller-reachable domain, memory/flags side
outputs, financial policy, helper closure, source/target compiled body match,
or whole-node equivalence is established. No acceptance gate is advanced.
Next: trace original callers and row producers to establish valid state/domain.

## Reproduce

Use Python3.12.14, Capstone5.0.6 and GNUobjdump2.47.20260726. The collector
refuses an existing new Rust implementation, preserving collection order.

```
python3 research/work-items/RE-004-signed-bound-kernel-115/freeze.py --output <new-output-directory> --objdump <GNU-objdump>
python3 research/work-items/RE-004-signed-bound-kernel-115/native.py
```

Only offline Python interpretation of original instructions; no captured
executable or Unicorn process, networking, wallet or chain operation.
