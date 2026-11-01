# RE-007: reserve reweighting subtracts old before adding new

Node #94's updater at `0x370e2a0` subtracts the old contribution with unsigned
saturation before adding the new one with unsigned saturation. This resolves
an explicit helper gap in the earlier reserve path. It differs from the
add-new-before-subtract-old order already documented for the fill writer.
The intermediate stores also determine what the recorder observes.

- Component/task: clearinghouses and risk, bounded RE-007 static follow-on.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, independently
  revalidated against upstream main before starting.
- Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred
  implementation was read or copied for this contract.
- Status: observed bytes, FDE/CIE records, branches, calls and stores;
  conditional numeric interpretation under the explicit scope below.
- Scope: positive `u32` old/new divisors, general unsigned combiner tail,
  one native-backed numerator slice, keyed wrapper and selected caller link.
  Complete input admission, general reserve production, economic denomination,
  recorder effects and caller rollback remain unresolved.
- No captured code or instruction emulator ran. No Rust reconstruction,
  compiled comparison, byte-window credit, safety conclusion or gate is claimed.

## Native scope and lineage

All coordinates are ELF virtual addresses; explicit file offsets, whole-body
hashes, full FDE/CIE records, LSDA-pointer identity, branch/call operands and
source Locations are retained in `evidence.json` and `decode.json`.

| Role | Half-open FDE extent | Bytes | Retained instructions |
| --- | --- | ---: | ---: |
| Updater | `0x370e2a0..0x370e693` | 1,011 | 286 |
| Keyed wrapper | `0x370e6a0..0x370e86f` | 463 | 129 |
| Existing caller, selected link | `0x37098a0..0x370a3c1` | whole body hash only | 8 at `0x3709f41..0x3709f65` |

The caller skips equal saved words, otherwise forms context `D+0x128` at
`0x3709f4d` and calls the wrapper at `0x3709f60`. The wrapper searches an
80-byte-entry map by 20-byte key, then a 64-byte-entry map by asset word.
Empty or missing entries return without updating the row or accumulator.
A match tail-jumps at `0x370e86a` with the inner value in `rsi`, outer entry
end `-8` in `rdi`, and the incoming new word in `edx`.

That outer final word is exactly the location loaded by reserve reader
`0x3708d50`; its instruction is independently rebound here. All nine selected
calls are retained: six updater recorder calls through RELATIVE slot
`0x5773190` to `0x358dcd0`, two wrapper hashes (`0x399c7a0`, `0x399c4a0`),
and the existing caller's direct wrapper call. Their external bodies remain gaps.

`fees-perp-settlement-94` names `0x370e2a0` as a next question;
`RE-004-update-leverage-path-94` leaves `0x370e6a0` external. The recorder's
previous byte-key overwrite observations are not claimed as new work here.

## Unsigned value and store contract

Given original aggregate `S` and completed contributions `C_old` and `C_new`,
the conditional returned value is:

```text
sat_add_u64(sat_sub_u64(S, C_old), C_new)
```

The storage must not alias, and modeled recorder continuation assumes it
returns without modifying the caller's owned fields. General production of
both contributions is outside scope. Native ordering is exact:

| Sites | Observation |
| --- | --- |
| `0x370e2ae..0x370e2b3` | Equal old/new words return before other row or aggregate reads. |
| `0x370e46f` / `0x370e49a` | Subtract old contribution and inspect unsigned borrow. |
| `0x370e474..0x370e480` | On borrow, call recorder before any aggregate store; assuming return, final store is exactly `C_new`. There is no intermediate zero store. |
| `0x370e49f` | Without borrow, store subtotal `S-C_old` before adding. |
| `0x370e4a5..0x370e4a8` | Add new contribution and inspect unsigned carry. |
| `0x370e4f9..0x370e505` | On carry, recorder sees the already stored subtotal; assuming return, select `u64::MAX`. |
| `0x370e4aa` | Final aggregate store precedes return. |

Subtraction's Location is `l1/src/qtys/impl_ntl.rs:26:1` at `0x56f1f30`;
addition's is `l1/src/qtys/mod.rs:829:1` at `0x56f1de8`. Earlier size-doubling
branches carry `l1/src/qtys/impl_sz.rs:9:1` at `0x56f1f00` and are retained
as bytes/edges, without a claim to their complete numeric behavior.

Two counterexamples show why order matters. For `S=2`, `C_old=10`, `C_new=5`,
this contract gives 5 and add-first gives 0. For `S=u64::MAX`, `C_old=5`,
`C_new=10`, this contract gives `u64::MAX` and add-first gives `u64::MAX-5`.
These are algebraic witnesses, not admitted production-state fixtures.

The synthetic numerator slice is explicitly restricted: row size `+0x20`,
selected count `+0x10` and word `+0x28` are all zero, with unsigned
`N=row+0x08` and strictly positive old/new `u32` divisors. Native conditional
moves select that baseline term; count zero forces the variable part to zero
before its division. Thus the contributions are `floor(N/old)` and
`floor(N/new)`. Valid producer invariants for these raw rows are not established.
The model is hand-derived algebra and store ordering, not an instruction interpreter.

## Reproduce and validation

From the repository root with the authenticated artifact:

```sh
python3 research/work-items/RE-007-reserve-reweight-order-94/verify.py --out work/reweight-review
python3 -m unittest discover -s tests -p test_reserve_reweight_order94.py -v
python3 research/work-items/RE-007-reserve-reweight-order-94/check_decoders.py \
  --llvm /path/to/installed/llvm-objdump \
  --binary artifacts/node/94/hl-node --out work/reweight-decoders
```

The verifier uses standard-library code and existing ELF/FDE/RELATIVE/Location
parsers. The separate decoder check uses installed GNU 2.44 and LLVM 19.1.7:
both agree on all 415 bounded instructions and all 600 caller boundaries.
Only eight caller instructions are retained. FDEs remain unwind ranges and
nearest-symbol decoder labels are not recovered function names.

Eight focused tests cover byte admission, exact ordering, unsigned widths,
integer rounding, positive equal-divisor shortcut and recorder-stop states.
All 504 changed cases within a 672-case positive-divisor sweep agree with an
independent removed/added closed form; an add-first variant differs on 205.
Eight compact cases are retained, while repetitive sweep rows stay transient.
These are model distinctions and byte-identity controls, not target execution
or independent semantic CFG equivalence. Most body corruptions are rejected
by frozen whole-body hashes; all 58 recorded branch encodings are exercised.

`VALIDATION.md` and `validation/` retain commands/results, including two
byte-identical regenerations under different hash seeds/timezones and Python
optimization. Full suite validation is coordinated separately; no full-suite
or hosted-CI result is claimed here.

Next question: recover the matching inner row's constructors and admitted
ranges, then close general numerator behavior and recorder effects before
implementing or comparing the full reserve path. No progress gate is requested.
