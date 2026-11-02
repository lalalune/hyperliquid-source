# RE-001: RPC timeout rounding in node #94

- Component: node-runtime; bounded RE-001/RE-012 helper closure.
- Target: Linux x86-64 node #94, SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Claim: static observations plus an explicit round-to-nearest-even model. No reconstructed Rust, target execution, full node claim or gate change.
- Gap: `gossip-rpc-timeouts-94/README.md` leaves the effect of callee `0x565f410` on scaled timeout values unresolved. This packet closes that local code/data/relocation question. Timer ownership remains open.
- No inferred can1357 source was used or copied. Captured byte excerpts retain their upstream rights; new analysis code and prose use the root MIT terms.

## Reproduce

From the repository root, with the pinned LFS artifact materialized:

```sh
python3 -B research/work-items/RE-001-rpc-timeout-rounding-94/verify.py
python3 -O -B research/work-items/RE-001-rpc-timeout-rounding-94/verify.py
```

To regenerate records explicitly, run the verifier with
`--write-records research/work-items/RE-001-rpc-timeout-rounding-94/records.json`.
This does not update the manifest or prose. Default verification compares original records byte-for-byte and checks an exact five-file manifest. The manifest excludes itself to avoid a circular hash.

The producer first authenticates the entire artifact, then uses the existing MIT ELF/FDE reader from `gossip_rpc_timeouts_static.py`. It reads original bytes; it never runs or transplants captured instructions. The machine-readable record binds the three parser dependencies. The disassembly is a separate GNU objdump 2.47 observation with Intel syntax and explicit VA ranges. Absolute local input paths in objdump output are redacted to the artifact's logical name and Windows line endings are normalized to LF; instruction and address line contents remain unchanged. Nearest dynamic-symbol labels in raw output are not function identities.

## Evidence

All addresses are linked ELF VAs. File offsets are independently resolved through the ELF section map. FDE extents are unwind-described ranges, not a whole-module function census.

| Item | VA extent / address | Observation |
| --- | --- | --- |
| Queried helper | `0x565f410..0x565f481` | One 113-byte FDE, both internal branches reach the final RET |
| Neighbor | `0x565f490..0x565f4e5` | One 85-byte FDE, byte-identical to helper suffix `0x565f42c..0x565f481` |
| Sign mask | `0x2082f0` | Two lanes of `0x8000000000000000` |
| Bias | `0x203ae0` | Two lanes of `0x3fdfffffffffffff`: the binary64 value immediately below 0.5 |
| Relative slot | `0x576f6d8` | R_X86_64_RELATIVE addend resolves to `0x565f410` |

The prefix copies the input, selects its sign bit, combines that bit with the positive bias, and performs scalar ADDSD. The shared suffix obtains the exponent, retains the original signed value when its exponent exceeds `0x432`, and otherwise masks fractional bits while preserving the sign of zero. It makes no calls and does not set MXCSR.

Four existing RPC timeout conversion sites multiply by the `1e6` constant at `0x20ae60`, then call through the same relocation slot:

| Owning FDE | Multiply VA | Indirect call VA |
| --- | --- | --- |
| `0x1fd4570` | `0x1fd475e` | `0x1fd4766` |
| `0x1fd4570` | `0x1fd500c` | `0x1fd5014` |
| `0x226bb20` | `0x226bcd0` | `0x226bcd8` |
| `0x435cb20` | `0x435ccc6` | `0x435ccce` |

## Implementation and comparison

No Rust implementation or compiled comparison is claimed. The Python model follows the observed addition and bit mask under round-to-nearest-even ADDSD. A separate exact rational reference rounds a finite input to its nearest integer with halfway cases away from zero. The 283 cases include signed zero, subnormals, both neighbors of 0.5, signed halfway values, the 2^51/2^52 transitions, infinities, NaN classification and 256 deterministic finite bit patterns.

This supports the local inference: under that explicit floating-point mode, the helper implements nearest-integer rounding with halfway cases away from zero before the caller's subsequent integer conversion. It is neither truncation alone nor ties-to-even rounding. The stored bias is deliberately less than 0.5: replacing it with exactly 0.5 mis-rounds the representable input immediately below 0.5 in the model.

Six controls corrupt the addition opcode, branch, sign mask, bias, neighbor RET and caller opcode. Static admission must refuse each. Separate semantic controls distinguish the actual bias from 0.5, ties-to-even and truncation-only behavior. These controls qualify the static interpretation and recorded inputs; they are not differential execution of the target.

## Results and limitations

See RESULT.md and records.json. This is a closed local helper question, not a full timeout/timer recovery or module reconstruction. No progress, component catalogue, byte-coverage registry or acceptance gate is changed.

The target's live MXCSR mode, exception flags, NaN payload behavior, platform runtime state, timer ownership and the surrounding caller's complete overflow/error paths remain unvalidated. No captured code, node, visor, live network, provider, signing or paid data service was executed.

Next question: trace the resulting integer microseconds to the timer constructor with its caller layout and error paths. Keep that separate from this already bounded helper result.
