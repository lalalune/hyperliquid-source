# Actual order consumer: prepared-row grouping admission

This advances user backlog HL115-043 / component RE-010. It closes the actual
`0x55650b0 -> 0x59316a0` consumer handoff and implements the latter's bounded
raw-mode group checks over its **prepared 72-byte rows**. It does not name the
public grouping variants or claim builder fee attribution.

Target: node/115 `hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All observations are static reads of the original ELF. Neither the executable
nor a target emulator was run. The Rust crate executes recovered source logic
only. Facts and controls bind the precise target, FDEs, instructions, dispatch
bytes, and dataflow described below; they are not an execution trace.

## Prior work and exact remaining scope

[#4132](https://github.com/lalalune/hyperliquid-source/pull/4132),
`RE-010-node115-order-staging-copy`, recovers staging into the 88-byte input,
including a second 32-byte-stride buffer and an option; it leaves their business
roles and consumer assignment open.
[#4116](https://github.com/lalalune/hyperliquid-source/pull/4116) associates the
`orders/grouping/builder` field table and the first orders vector, without
assigning the numerical values used below. This contribution starts at the
real downstream consumer and stops at its late group admission boundary. It
does not duplicate the staging loop, parse the wire fields again, or promote
proximity to a semantic field name. The second buffer and builder business
semantics remain open.

## Actual carrier and preparation

At `0x55650ff..0x5565143`, the actual order consumer copies all 88 input bytes
from its fourth argument to `rsp+0x1c0`; notably input `+0x50..+0x57` goes to
`rsp+0x210`. It passes that same copy to `0x59316a0` at `0x5565181`, with a
copied 20-byte identity and the same state pointer. Status `0x1a2` is required
before the consumer loads the returned vector at output `+8/+0x10/+0x18`.

Preparation loads the raw u32 mode at input `+0x50` and u32 parameter at `+0x54`.
Only mode 3 passes that parameter to the earlier helper `0x3bf0630`; the other
modes pass zero. This helper's state-dependent admission is a prerequisite,
not a callback simulated by the source projection.

The first input vector is traversed at stride 56. Input row byte `+0x36 == 2`
ends preparation; otherwise `0x517b760` receives the 56-byte row and identity.
Each success returns 72 bytes at its output `+8`, copied into the prepared
vector. The append increments its count and pointer by 72 (`0x59317e0..1831`).
Errors leave this path. The transformation itself remains opaque here.

At `0x59319e8..0x5931a67` the prepared vector, preserved second descriptor and
remaining input bytes are assembled. The raw mode/parameter are reloaded and
copied to result `+0x58/+0x5c`. The parameter is capped at 100,000,000 for mode
3, and an empty prepared vector produces status `0x6e`. Optional-buffer and
mode-3 authorization branches can run before late group admission. The Rust
function's contract begins **after these earlier guards have passed**.

## Recovered late group checks

The signed-relative table at `0x93700c` has four entries:

| Raw mode | Target | Late group behavior |
| --- | --- | --- |
| 0 | `0x5931acd` | assemble success |
| 1 | `0x593212c` | require first row byte `+0x19 == 2`, then check following rows |
| 2 | `0x5932147` | check all rows, including the first |
| 3 | `0x5931acd` | assemble success after earlier mode-3 checks |

Mode 1's expected byte `+0x30` is the first row's byte XOR 1; mode 2 uses the
first row's byte unchanged. These are valid Boolean-layout inputs. The word
at first-row `+0x28` is retained as an exact 64-bit comparison key.

For each checked row, `0x5932168..0x5932195` performs these checks in order:

1. Byte `+0x19` must differ from 2; failure `0x73`.
2. Byte `+0x30` must equal the expected byte; failure `0x6f`.
3. Byte `+0x31` must equal 1; failure `0x70`.
4. All eight bytes at `+0x28` must equal the first row's word; failure `0x74`.

Mode 1's prefix-kind failure is `0x72`. After every checked row passes, the
remaining count is decremented and unsigned-compared with 2: exactly **one or
two checked rows** pass. Zero or at least three gives `0x71`. Thus mode 1
admits one prefix plus one or two checked rows; mode 2 admits one or two total
rows. A malformed third row can fail before the count rejection. Success
copies the prepared record and writes status `0x1a2` at `0x5931b24`; it is not
an order execution or fill result.

## Source and validation

`src/node115-order-group-admission` implements this raw-layout decision logic.
The source explicitly rejects unsupported modes and malformed Boolean bytes
as **projection premise errors**, not invented native statuses. Modes 0/3 skip
only the late group rules; the API does not pretend to satisfy earlier guards.
Tests cover both Boolean directions, the full small count matrix, field-error
precedence, malformed overlong groups, full-word identity comparison,
unread-byte independence, and explicit source premise errors. Debug, release,
and warning-free Clippy checks pass.

Reproduce the static packet with an independently obtained target:

```sh
python3 research/work-items/RE-010-node115-order-group-admission/verify.py --target /path/to/hl-node
cargo test --manifest-path src/node115-order-group-admission/Cargo.toml
cargo test --release --manifest-path src/node115-order-group-admission/Cargo.toml
cargo clippy --manifest-path src/node115-order-group-admission/Cargo.toml --all-targets -- -D warnings
```

The packet contains two windows (3,829 bytes / 749 instructions), 186 facts and
186 independent negative overlays. Each changed fact must be rejected against
unchanged records. A pass establishes reproducible evidence anchors; semantic
interpretation still requires the dataflow review above.

## Limits and downstream use

Downstream order reconstruction can now reuse this exact prepared-row
admission rule, after proving its own earlier admission inputs. It cannot yet
label the raw modes from the wire decoder, identify the second 32-byte buffer,
compute builder fee attribution, model the opaque row transform or authorize
state-dependent input. This does not establish transaction rollback, partial
execution, fills, queue priority, fee accounting or full batch semantics. Error
cleanup, allocation failures and unwind behavior are outside this result.
