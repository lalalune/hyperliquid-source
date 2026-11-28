# RE-006: book-level ring row threshold arithmetic

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations, a mathematical proof of one integer expression, and limited dataflow interpretation. No captured code is executed or emulated; no component gate is claimed.

## Question and prior work

[#7835](https://github.com/lalalune/hyperliquid-source/pull/7835) traces a level's 32-byte ring row to a comparison that gates consumption but deliberately leaves its operands opaque. Which row fields feed the arithmetic, and what exact integer division is implemented by the multiplier before that comparison? This packet examines that caller-specific arithmetic; it does not identify a source crate, infer field units, or assert full time/date behavior.

## Static evidence and interpretation

The selected row supplies three zero-extended dwords from offsets `+0x10`, `+0x14`, and `+0x18`. The first feeds a multi-instruction transformation ending in a sign-extended integer in `rdi`. The second remains in `rdx`, and the third in `rsi`, until used at `0x518e954` and `0x518e957`. The verifier decodes the intervening instructions and rejects writes to those registers and their aliases. The first transformation's meaning is not established here.

At `0x518e94d`, the code multiplies the sign-extended integer by 86,400, adds the second dword, multiplies by 1,000 and adds the third dword transformed as `(x * 0x431bde83) >> 50`. These are machine-width operations; overflow behavior must be considered before assigning a higher-level numerical interpretation. A signed `test`/`cmovle` selects zero when the resulting signed value is nonpositive. The code then adds an earlier stack operand and selects all-ones on unsigned carry. Finally an unsigned-below branch returns to the caller when the qword at stack `+0x10` is smaller; equality takes the consuming continuation documented in #7835. The origin and units of the two earlier stack operands are not proved here.

For every unsigned 32-bit `x`, the multiply/shift term equals `floor(x / 1,000,000)`. The verifier proves this without sampling: with `S=2^50`, `d=1,000,000`, `m=ceil(S/d)=1,125,899,907`, and `e=m*d-S=157,376`, writing `x=q*d+r` gives `x*m=q*S+q*e+r*m`. Since `q<=4294`, `r<=999999`, and `4294*e+999999*m < S`, the remaining term is always less than `S`. This proves the arithmetic identity only; it is not a target runtime comparison.

`records.json` retains the contiguous 253-byte / 57-instruction interval `0x518e89f..0x518e99c` of FDE `0x518e690..0x518f039`. Twenty-five static instruction facts and 19 in-memory opcode/operand mutations bind the chosen fields, constants and branch to the authenticated ELF. `offline-log.json` is the actual verifier result; the proof and register-preservation checks run in the same verifier.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-ring-threshold-arithmetic/verify.py
(cd research/work-items/RE-006-node115-book-ring-threshold-arithmetic && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the entire target and decodes from the FDE start. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

The 253-byte interval is not complete coverage of the helper. Row production, the first field's transformation, all input ranges, time or calendar meaning, stack operand provenance, signed overflow consequences, dynamic behavior and complete book semantics remain unresolved. Next, bind the producing code and the two stack operands before assigning types or units.
