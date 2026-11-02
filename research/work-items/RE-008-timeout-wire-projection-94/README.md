# RE-008: timeout variant-2 serialization projection

- Component: consensus; task RE-008, partial static wire research.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Pinned reference: can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`; field names are research leads, no reference code copied.
- Question: which fields, widths and row order does tag 2 serialize, and how are its nested QC signatures represented?

The native writer appends signer 20, timeout round, three QC words, hash 32,
vote count and input-order QC vote rows. Each row contains signer 20, eight
variable-width u64 values loaded from its 64 signature bytes, and one raw
recovery byte. The outer timeout signature is excluded from this selected
writer. [PROOF.md](PROOF.md) states the exact offset formula, local branches,
caller relation, helpers and memory/normal-return premises.

Observations are native loads, stores, transfers, widths and table values.
The timeout/QC/signer/signature field names are inferred from existing typed
admission and timeout evidence. Cryptographic meaning and full digest semantics
remain unknown here. No progress gate changes.

| New body | Complete FDE range | FDE VA |
| --- | --- | --- |
| timeout writer | `4778820..4778a62` | `efbd00` |
| timeout sizer | `4778a70..4778be2` | `efbd4c` |
| QC vote-list sizer | `485b780..485b818` | `f0d7ec` |
| QC vote-row sizer | `4c7e7a0..4c7e830` | `f44420` |
| nested signature writer | `4df20d0..4df2242` | `f4fc9c` |
| nested signature sizer | `4df2250..4df2392` | `f4fce0` |

The complete shared scalar, dispatcher and wrapper bodies close the selected
serializer route. They are context/dependencies, not additional novel recovery.
Unclaimed verifier, signing and digest-root owners have only four bounded
corridors exported, with their complete body/FDE identities retained. Total:
15 full FDEs and 4 corridors, 6036 selected bytes / 1509 instruction rows.
There is no matched-byte denominator or Rust implementation in this packet.

## Reproduce

Requirements: hydrated authenticated node #94, Python 3, GNU objdump 2.44,
LLVM objdump 19.1.7. Existing tools are used without installing dependencies.
No network, captured execution or instruction evaluator is needed by these
commands. Run from repository root:

```sh
python3 research/work-items/RE-008-timeout-wire-projection-94/build.py \
  --llvm /path/to/llvm-objdump --out work/timeout-wire-fresh
diff -r research/work-items/RE-008-timeout-wire-projection-94/observed work/timeout-wire-fresh
python3 research/work-items/RE-008-timeout-wire-projection-94/verify.py \
  --llvm /path/to/llvm-objdump --report work/timeout-wire-validation.json
python3 -O research/work-items/RE-008-timeout-wire-projection-94/verify.py \
  --llvm /path/to/llvm-objdump --report work/timeout-wire-validation-optimized.json
(cd research/work-items/RE-008-timeout-wire-projection-94 && sha256sum -c MANIFEST.sha256)
```

Pass `--llvm`, set `LLVM_OBJDUMP`, or put `llvm-objdump` on PATH. The selected
environment used `/workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump`.
Native output headers replace only the supplied
input path with `artifacts/node/94/hl-node`; no instruction bytes are masked.
Standalone LOCK rows are joined when comparing native instruction partitions.
Full exports otherwise preserve native tool text, including irrelevant nearest
dynamic-symbol labels. `validation.json` records actual tools and results.

The verifier makes two fresh exports and compares every output byte to the
committed exports/records. It then runs 34 target-derived semantic-window byte-identity
controls, changes all 10 dispatch-table entries, the tag constant and the FDE range.
Four native JNE displacement mutations bypass mandatory operations; a fifth
native mutation makes success unreachable. Those graph controls turn off
whole-image and witness/body-equality checks. This exercises the independent
local graph conditions. It tests static evidence guards, not target execution.

## Ownership and scope

At intake, all 1405 available historical PR records were searched for the
six new-body addresses and timeout preimage/signing/serialization/wire phrases.
No matching body/projection contribution was found. Open #1391 covers tag 1
QC vote preimages and explicitly leaves other variants unresolved; #1366
covers consensus errors. Their native-context work is credited, not counted
as this result. Committed `RE-008-vote-timeout-path-94` explicitly stubs digest
and signature bytes. `RE-008-block-admission-94` identifies caller fields but
also stubs the digest; neither proves this wire projection. This search cannot
detect undeclared work or all PR comments.

No shared tools, imported evidence, Rust components, catalogue or progress
records are changed. The packet stays in this directory; one focused root
test participates in the repository suite. New analysis
and Python are independently authored under root MIT. Target rights and
reference licensing remain unchanged.

## Results and limitations

See `VALIDATION.md`, `validation.json` and `repository-validation.json` for
observed commands/results. The full `make test` is deferred to coordinator
integration; no broad test or hosted-CI success is claimed. Captured-instruction
emulation is opt-in and its enabling flags were unset. Repository verification, catalogue
consistency and inventory reproduction are reported separately from the new
manual semantics proof.

The contract requires stable, valid, disjoint memory and ordinary normal
callee behavior. Invalid inputs, allocation/clock/grow effects, exceptional
paths, complete hash/preimage behavior, cryptographic validity, wire decoding,
state transition correctness and whole-node equivalence remain unresolved.
Next question: bind the decoder for this tag to the recovered variable-width
signature limb representation and qualify noncanonical/error cursor behavior.
