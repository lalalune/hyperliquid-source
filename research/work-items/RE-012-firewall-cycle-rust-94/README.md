# RE-012 / node-runtime: independent firewall-cycle decision Rust projection

## Question and provenance

The baseline has static evidence for the firewall cycle before its loader
call, but no Rust component at `src/node94-firewall-cycle/`. Recover the
established skip/throttle/check/update decisions as one conditional pure API.

- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Node94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Existing project-authored evidence/model: `tools/firewall_update_cycle_static.py`
  and `research/work-items/firewall-update-cycle-94/`.
- ELF virtual addresses throughout; no runtime rebase, normalization mask or
  imported-pin change. The unlicensed reference is not implementation source.
  This contributes new Rust, not a new function-discovery claim.

## Observations and recovered projection

`evidence.json` binds the complete capture digest, maintained producer hash,
fresh static records, unique non-overlapping FDE records and full body hashes.
The complete LLVM listings cover `0x28f6960..0x28f7302` (2,466 bytes, 483
instructions) and `0x27cdf00..0x27ce16d` (621 bytes, 148 instructions).
Capstone independently agrees with all 3,087 bytes / 631 boundaries. LLVM
prints LOCK as its own line; the checker joins only a contiguous `f0`/`lock`
display prefix to the following instruction. No byte is omitted or masked.
These are disassembly bounds, not full semantic-recovery bounds.

The maintained producer checks the section callers, branches, helpers, literal
names, equality fields and relocations. Within that evidence:

- The byte at poller `+0x260` skips the sections only when equal to 1, with
  loader flag 0. Arbitrary nonzero bytes are not the same predicate.
- An absent prior timestamp tag at `+0x280` permits maybe-update. Otherwise
  the supplied elapsed seconds must be strictly greater than interval
  `+0x278`. Equality and unordered comparisons do not permit it.
- Compute and equality-check run on the non-skip route even if maybe-update
  is throttled. The original compute helper receives the ran flag.
- Update runs iff at least one of the supplied map/set/set equality results
  is false; normal loader flag is 1.

The new `Plan` returns these decisions. It receives raw flags, the time-helper
return and equality results; it does not fabricate helper implementations.
For example, elapsed=interval with an unequal second set suppresses only
maybe-update, while compute/check/update remain selected.

## Independent comparison and negative controls

`verify.py --prepare` froze evidence and corpus before Rust existed, and
refuses to prepare when the source already exists. The 27,088 cases enumerate
raw skip bytes 0/1/2/255, timestamp tags 0/1/high-bit/max, all eight equality
combinations and 14×14 floating bit patterns, plus 2,000 seeded raw-bit cases.
Patterns include signed zero, subnormal, adjacent threshold values, infinities
and positive/negative quiet or signaling NaN encodings. These are scalar
counterfactual tests, not evidence that every input is reached at runtime.

A truth-table formulation is checked against the maintained static `cycle`
and `changed` models. The independently linked Rust runner receives input
words, not expectations. With rustc 1.94.1, edition 2021, warnings denied and
overflow checks enabled, debug/optimized/repeated optimized builds each match
all rows; repeated optimized library hashes agree. Three own unit tests pass.
Seven separately compiled semantic mutations complete the protocol and fail
comparison:

| Mutation | Mismatches |
| --- | ---: |
| Treat every nonzero skip byte as skip | 14,533 |
| Allow elapsed equality | 936 |
| Allow unordered comparison | 5,402 |
| Invert absent-timestamp gate | 14,641 |
| Throttle compute as well | 11,233 |
| Change equality AND to OR | 15,642 |
| Return loader flag 0 on normal route | 20,808 |

`results.json` retains compiler, corpus, source/harness/verifier fingerprints,
comparison and decoder counts, library rebuild hashes and control results.
Raw inputs, expectations and process/compiler/command outputs are retained
locally in the ignored reproduction output directory.

## Reproduction, validation and remaining gaps

```sh
python3 -B research/work-items/RE-012-firewall-cycle-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/firewall-new --controls
python3 -B -m unittest discover -s tests -p test_firewall_update_cycle_static.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a new output directory. Python/Capstone 5.0.7, LLVM 23.1.4 and rustc
1.94.1 were used. The 20 existing target-evidence tests pass without skips;
repository-wide results are in `VALIDATION.md`.

No captured node, networking or firewall operation is performed. The Rust API
is a bounded policy projection: IP collections, equality-helper bodies and
their call effects, locks/atomics, sleep, timestamp writes, compute/loader
effects, ownership/unwind paths, FP exception flags and original ABI remain
unclosed. Source/input agreement does not prove native execution, machine-code
identity, whole-node integration or component completion. No progress gate,
catalogue, pin, shared tooling, existing test or external dependency is changed.
