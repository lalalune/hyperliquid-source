# RE-001 / action dispatch: selected oracle update stage order

Question: after the existing gate returns, which length/status/index checks run
before apply, and how is its returned raw word routed? Scope: one core's selected
normal-helper stages, controls and packet. No complete oracle mutation, timer
policy, financial/chain operation or action-dispatch gate is claimed.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed can1357-hl reference revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, handler
`23_validator_l1_update_reference_oracle.rs`, is a lead only; no code is copied.

## Observations

ELF virtual addresses, no masks. Actual FDE `0x2707190..0x2707742`:
**1,458 bytes / 285 instructions**, complete contiguous export, raw FDE/CIE,
hash and selected branch/call boundaries. Only the post-membership stage region
is modeled; earlier validator lookup and initial Dex/root preconditions are excluded.

The declared model begins at normal return from `0x325ed00` at `0x27072d0`.
It does not infer that helper's clock/throttle effects from the reference name.

| Selected stage | Continue condition / other route |
| --- | --- |
| Gate result word | 390 continues; otherwise forward its opaque result |
| Action length +0x10 | <10001 continues; otherwise status 323 |
| Action length +0x40 | <10001 continues; otherwise status 323 |
| Helper `0x27448f0` | Word 390 continues; otherwise forward its result |
| Selected slot vs array length +0x3378 | Slot < length continues; otherwise captured unwrap-failure route |
| Apply helper slot `0x5774988` → `0x3709040` | Raw first word determines following route |
| Normal post-apply path | Calls `0x325eec0`, then stores status 390 if helpers return normally |

Only **two** selected vector-length checks appear before external validation.
The descriptor at action `+0x18` is passed onward through an auxiliary argument;
this does not assert that its contents/length are unchecked by later helpers.
Length names oracle/external-perp follow the reference, not recovered Rust types.

After apply, the first returned word is loaded into RCX and negated. Six
MOVUPS/MOVAPS pairs preserve OF until `JNO 0x2707529`. NEG overflows only for
raw `0x8000000000000000`; that class takes the opaque packet-forwarding route.
Every other declared raw word reaches the post-apply path. These raw classes do
not establish a general Rust Result ABI, valid helper representation, or per-field
success semantics. The in-range slot uses an observed 0x138 stride before apply.

## Inferences and limits

Oracle/gate/validation/apply labels follow the reference and call context. Earlier
authorization, missing-root failure, exact payload types, valid input/value domains,
helper effects, oracle state updates, timing, post-apply effects, ownership and
unwind remain unclosed. In particular this packet does **not** claim that a timer
is charged before invalid input, or identify a vulnerability. All helper outcomes
are supplied conditional raw results; no live validator, exchange, oracle, process,
network, signer or chain action is used.

Before: a reference stage narrative without caller-bound result/flag evidence.
After: exact ordering, two selected length operands, helper/slot gates and the
flag-preserving niche branch are digest-bound. Next question: close gate, apply
and post-apply helper effects before assigning a complete typed mutation contract.

## Reproduction and checks

Python 3.12.14, stdlib static readers; optional Capstone 5.0.6 x86-64 Intel.

```
python tools/oracle_stage_order.py --out research/work-items/RE-001-oracle-stage-order-94/records.json
python research/work-items/RE-001-oracle-stage-order-94/export_disassembly.py
python -m unittest tests.test_oracle_stage_order -v
```

Six focused methods pass in 0.966 seconds: all 65,536 declared gate words,
both length boundaries/priorities, slot boundaries and raw NEG-overflow neighbors.
Changing the real JNO to JO or a limit immediate changes the modeled route and
bindings reject it. Additional capture controls cover calls, statuses, preserved
flags through moves, field offsets, FDE and identity. Raw domains include states
not proved valid or reachable. Make is unavailable; required Python commands ran
directly. Full suite: **363 tests in 164.619 seconds; 7 failures, 16 errors,
21 skips**. All six new methods pass. Existing Windows newline/POSIX-path/native
tool constraints remain; this branch excludes unmerged #227. Doctor reports
missing prerequisites. Eight artifact sizes/digests pass before missing GPG
prevents signature verification. Imports reject the Windows reference checkout;
catalogue-check rejects backslash paths. Reproduce stops at artifact verification.
No full-suite/signature/hosted-CI or native-equivalence success is claimed.
