# Call-result reserve words into the selected remaining frame

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. Partial HL115-071 / RE-011 advance. The captured program was not executed or emulated.

This packet closes one concrete return-side boundary in `0x2962aa0`: a copied 90-hex-byte call result supplies reserve words to the selected remaining 512-byte frame. Raw statuses 1–4 preserve the returned unsigned word separately and accumulate the signed word into the remaining frame. Other statuses reaching this normal arm fold the signed quantity into the returned unsigned quantity with endpoint saturation, leaving the frame's signed word unchanged.

## Prior work and bounded gap

[#3931](https://github.com/lalalune/hyperliquid-source/pull/3931), `RE-011-sstore-gas-refund-115`, already owns the SSTORE producer's updates to interpreter `+0x190/+0x198` and parameter `+0x150`, but leaves frame settlement open. [#3332](https://github.com/lalalune/hyperliquid-source/pull/3332) covers the earlier payer-deduction fragment `0x29634ef..0x2963796`. [#2114](https://github.com/lalalune/hyperliquid-source/pull/2114) identifies the eth_call executor handoff. None of their producer or routing observations is new here.

The new scope binds actual result offsets, frame selection, raw-status gates and the two stores at this return boundary. It does **not** yet prove that these result words came from a particular SSTORE, nor complete frame/transaction settlement. The other result arm, parameter policy, gas `+0x188`, refund `+0x1a0`, returned-buffer ownership and top-level commit/revert remain open. No whole backlog or component gate is advanced.

## Native lineage and exact contract

At `0x2965134`, the selected path requires frame-container tag 1. It reads the frame index and backing pointer, uses a 512-byte stride, and may step back one index according to the current frame's byte `+0x1f8`. `0x2965187` computes the remaining frame pointer. At `0x2965342`, a `0x90`-byte result is copied from stack `+0x760` to `+0x210`. Its fields are then read as follows:

| Result offset | Loaded at | Use in this projection |
| --- | --- | --- |
| `+0x58` | `0x2965358` | unsigned 64-bit returned word, saved at stack `+0x38` |
| `+0x60` | `0x2965365` | signed 64-bit returned word, saved at stack `+0xc0` |
| `+0x70` | `0x2965388` | raw status byte |

The frame pointer is preserved at `0x2965385`/`0x29653bd` and reloaded into R9 at `0x2965440` or `0x2965733`. The surrounding return-buffer replacement and cleanup are real intervening operations; their ordinary return is a premise of this selected projection.

Write `U` for result `+0x58`, `S` for result `+0x60`, and `P` for the frame's old signed word `+0x198`:

| Selected normal status | New frame `+0x190` | New frame `+0x198` |
| --- | --- | --- |
| raw 1, 2, 3, 4 | `U` | clamp `P + S` to the signed 64-bit range |
| other raw status reaching this arm | clamp `U + S` to `[0, 2^64−1]` | unchanged |

This classification follows both gates, not just `status < 5`: the preceding mask `0x3f001e` admits statuses 1–4 and 16–21 for separate gas handling, and only 1–4 reach the signed accumulation. Raw 0 takes the nonmember path. Raw 54 branches away at `0x2965738` before the normal fold and is explicitly rejected by the Rust projection. The result's valid native variant set is not inferred from arbitrary-byte test inputs.

The successful merge uses the overflow flag to choose the signed endpoint at `0x2965519..0x2965531`, then overwrites `+0x190` and `+0x198` at `0x296553a`/`0x2965541`. The other arm captures carry and the sign of `S`, selecting either the in-range sum, zero or unsigned maximum at `0x2965566..0x296558c`. It writes only `+0x190`. Separate gas and refund operations can leave the normal path and are not silently treated as successful by the source projection.

## Source and validation

`src/node115-child-reserve-fold` implements these two word updates with raw offset names. It accepts actual result-word inputs and has no simulated executor, callback or invented SSTORE behavior. Status 54 returns an explicit unsupported-branch result without changing the frame. Integration into a complete finalizer still requires the surrounding branch and ownership contracts.

Two tests pass in debug and release, with strict Clippy. The wide-integer oracle checks 165,240 combinations: 255 raw statuses, eight unsigned endpoints and nine choices for each signed operand. It computes expectations using i128 range clamping, independently of the implementation's native-width saturating operations. A separate test checks status selection and the unchanged state for unsupported status 54. These synthetic projection checks do not establish that every raw status is reachable.

The static verifier binds 3 original windows, 744 bytes / 136 instructions, 60 facts and 60 changed-byte controls to the full artifact digest. Controls cover the actual frame stride and pointer, result offsets, classification gates, overflow selection and store destinations. Static lineage supplies the interpretation; the verifier rejects evidence drift.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-011-node115-child-reserve-fold/verify.py --target /path/to/original/hl-node
cargo test --offline --manifest-path src/node115-child-reserve-fold/Cargo.toml
cargo test --offline --release --manifest-path src/node115-child-reserve-fold/Cargo.toml
```
