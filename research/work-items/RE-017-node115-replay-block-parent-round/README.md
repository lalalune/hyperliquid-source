# RE-017 · Node #115 replay Block parent-round gate

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `cfeaee133b33ce9450a7434af19515b82171a8c6`. Addresses are original ELF virtual addresses within the FDE at `0x5a82670..0x5a89535`.

## Question

After the [Block identity gate](../RE-017-node115-replay-block-identity-gate/README.md), what does the receiver compare to distinguish an older child Block from one it can process? The prior packet stops at the selected pair and successor staging. This packet establishes the next comparison and the source of its baseline, including how an empty versus populated receive buffer changes it.

## Observations

Let F be the current future and A the non-null first owner in the selected Block pair. The store at `0x5a87523` saves F at F+0x208, which the code reloads into RAX at `0x5a87557`. The code stages three qwords:

| Diagnostic label | Future field | Value on the selected path |
| --- | --- | --- |
| `round` | F+0x1f0 | Select A+0x60 if marker M occurs at A+0x28, otherwise A+0xb0. Increment the word and map wrap to all ones. |
| `parent_round` | F+0x1f8 | Select A+0x60 if A+0x28 equals M, else A+0x58 if A+0xb8 equals M, else A+0xe8. Read that word directly. |
| `last_recv_round` | F+0x200 | Start from F+0x110. If F+0x10 is nonzero and the computed tail address from F+0x08 is nonnull, use the saturating successor from the tail row's first owner, using the same two-way word selection as for `round`. |

M is `0x8000000000000001`. The tail address is F's buffer pointer plus `16 * count - 16`. At `0x5a87663` the code compares the second and third staged words, and `jae` at `0x5a87666` enters the continuation at `0x5a87a52` on unsigned equality or greater. This calls through slot `0x64ebb78` (relative relocation to `0x4fad710`). The below-baseline arm instead prepares three pointers to these fields in the same order as the labels in the literal at `0x44ccc7`, with message text beginning `received old client block, is peer behind?` at `0x93ba86`. Its first formatting call uses slot `0x64e0b18` (relative relocation to `0x150b310`). The label names describe the diagnostic's projections.

A fixture representing the first received Block and a fixture with queued Blocks require separate baseline cases. In particular, the comparison uses the incoming **parent** word and the existing baseline, while the incoming successor is a diagnostic operand.

## Validation and limits

```sh
python3 -B research/work-items/RE-017-node115-replay-block-parent-round/verify.py
```

The [retained instruction windows](windows.txt) include both paths through the comparison. The [offline run](offline-log.txt) contains digest, verifier and independent disassembly comparison results. The verifier checks selected bytes against the pinned ELF and their FDE, validates the two indirect slots and the diagnostic string bytes, and compares three marker-branch layouts with an independent table of effective offsets. Synthetic arithmetic controls cover empty and populated receive buffers, tail versus non-tail, equality, a lower parent, unsigned comparison and saturating increments. A changed witness tests the byte comparison itself.

The captured executable is read as data. F+0x110's initial value, meanings of unrelated queue fields, schedulability, signature validity, application of a checkpoint or Block and state-root equivalence remain open.
