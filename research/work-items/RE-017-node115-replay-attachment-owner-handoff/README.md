# RE-017 · Node #115 replay Block attachment owner handoff

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `c2772e3b1c742734af159c2c42c9541c7ebb7ac2`. Addresses are linked ELF virtual addresses.

## Question

The [payload-pair packet](../RE-017-node115-replay-payload-pair/README.md) identifies the optional attachment owner in a decoded Block pair. After the [Block identity check](../RE-017-node115-replay-block-identity-gate/README.md) and [parent-round comparison](https://github.com/lalalune/hyperliquid-source/pull/7266), how do the present-attachment and empty-Block cases actually form the input for the downstream replay worker?

## Observations

Let F be the replay future, A the selected Block owner and B its optional attachment owner. On the parent-at-least-baseline path, `0x5a87a64` calls a slot which resolves to `0x4fad710`. It supplies result storage at stack+0x3190, A in RSI and B in RDX. The input pair is taken from the staged fields at F+0x1d8/+0x1e0, and the intervening instructions on this path preserve RSI and RDX.

| Selected input | Helper result |
| --- | --- |
| B is present | `0x4fad72b..0x4fad733` stores the same A and B pointers at output+8/+0x10 and tag `0x2e` at output+0. This branch obtains its result without allocating another attachment owner. |
| B is absent, A+0x20 is zero and allocation returns nonnull | `0x4fad74b` reads the Block count operand. The selected empty path stages `(0, 8, 0)`, allocates `0x28` bytes and initializes five qwords `(1, 1, 0, 8, 0)`. `0x4fadad7..0x4fadadf` writes A and this new owner in the same output slots then reaches the same tag store. The shape agrees with the previously established owner prefix and records an empty attachment collection rather than keeping the absent pointer. |

The caller recognizes `0x2e` at `0x5a87a6a` and copies the pair from the result into F+0x1c8/+0x1d0. On the selected equality continuation, it writes the pair to F+0x238/+0x240 and passes F+0x230 to `0x5a897e0` at `0x5a8438a`. The preceding qword of that input is the future pointer reloaded from F+0x1e8. This identifies the first consumer input to use for both an explicit attachment owner and a Block with zero count that reaches the empty-owner construction.

The selected flow assumes valid owners, normal allocation/returns and unchanged comparison words before the equality continuation. The nonempty Block reconstruction when B is absent, alternate result tags, complete ownership lifetimes, worker internals, replay inputs and roots remain open.

## Reproduction

```sh
python3 -B research/work-items/RE-017-node115-replay-attachment-owner-handoff/verify.py
```

The verifier authenticates the [instruction windows](windows.txt), checks dispatch, stack-field and owner-field displacements and covers both selected arms plus altered byte and swapped-owner controls. The [offline run](offline-log.txt) records the verifier output and selected independent disassembly. The target is read as ELF data.
