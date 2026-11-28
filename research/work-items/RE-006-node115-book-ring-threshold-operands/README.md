# RE-006: book-level ring comparison operand origins

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Static observations, limited dataflow interpretation and one mathematical integer proof. No captured executable is run or emulated; no component gate is claimed.

## Question and prior work

[#7864](https://github.com/lalalune/hyperliquid-source/pull/7864) binds the ring row's arithmetic to a comparison but leaves the previously prepared stack operands open. What inputs and constants feed those operands? Existing [#4238](https://github.com/lalalune/hyperliquid-source/pull/4238) identifies `0x63efe40` as a rounding helper via slot `0x64e1890`; this packet adds its book-level caller connection and does not re-claim that helper's complete contract. It does not assign calendar or time units to the structures.

## Static evidence and interpretation

At entry the helper saves the incoming `xmm0` binary64 and the `rsi` context pointer. On the nonzero level-`+0x48` path it reads three 32-bit context fields at `+0`, `+4`, and `+8`. The first is transformed through shifts and integer arithmetic; the second is temporarily saved; the third is multiplied by `0x431bde83` and shifted right 50 bits. Assuming normal SysV ABI preservation across the intervening helper call, `r14` retains this zero-extended third field.

For all unsigned 32-bit `x`, `(x * 0x431bde83) >> 50 = floor(x / 1,000,000)`. The verifier proves this without sampling: with `S=2^50`, `d=1,000,000`, `m=ceil(S/d)=1,125,899,907`, `e=m*d-S=157,376`, and `x=q*d+r`, both `q<=4294` and `r<=999999`; hence `q*e+r*m < S`. This mathematical identity does not execute the target.

The transformed first field is sign-extended, multiplied by 86,400, combined with the second field, multiplied by 1,000 and combined with that quotient. The resulting machine-width signed value is tested and a nonpositive result selects zero; the selected value is stored at stack `+0x10`. Earlier, the saved `xmm0` is multiplied by binary64 `1000.0` at `0x459a60` and passed through slot `0x64e1890`, whose `R_X86_64_RELATIVE` addend points to `0x63efe40`. The following floating-point comparisons and conversion instructions reference binary64 constants `2^64`, `2^63`, and the largest representable binary64 below `2^64`, and their selected result is stored at stack `+8`. This packet binds the inputs, instructions and constants; it does not give a complete NaN/infinity/rounding truth table or infer the float's units.

At the later comparison, stack `+0x10` is compared against a row-derived value plus stack `+8`. The verifier checks that the straight-line first ring-evaluation interval contains no direct `rsp`-relative writes overlapping these two stack slots. It does not prove absence of indirect aliases or behavior across later loop iterations. Field validity, helper ABI and normal returns are assumptions; integer overflow and the first field's higher-level meaning remain open.

`records.json` retains 409 bytes / 90 instructions in three windows of FDE `0x518e690..0x518f039`. Forty-eight instruction, literal and relocation facts and 26 in-memory mutations bind the selected operations to the authenticated ELF. The verifier also checks the all-u32 quotient bound and direct stack stores. These are static checks, not target runtime tests. `offline-log.json` is the actual result.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-ring-threshold-operands/verify.py
(cd research/work-items/RE-006-node115-book-ring-threshold-operands && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the entire target and decodes from the FDE start. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

The 409-byte selection does not cover the whole helper or all paths. It does not establish source crate identity, context production, numerical units, edge-case float behavior, overflow-free input ranges, indirect stack aliases, concurrency or end-to-end order semantics. Next, trace callers that produce the 12-byte context and floating input, then validate the first-field transformation against an independently pinned source or target-grounded derivation.
