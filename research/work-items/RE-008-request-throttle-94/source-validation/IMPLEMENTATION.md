# Retained request-row values: implemented and qualified

The real dependency-free `node94-consensus-admission` crate now exposes
`request_throttle::RequestThrottle`. It owns a supplied map keyed by unsigned
round and all32 hash bytes. Calls retain the original timestamp, insert every
reason before suppression, and emit once at or after the computed deadline.
The state is separate from existing block admission's tag-zero removal context.

Read [SOURCE-PROOF](SOURCE-PROOF.md), then the immutable parent
[CONTRACT](../CONTRACT.md), [native PROOF](../PROOF.md) and
[CALL-FRAMES](../CALL-FRAMES.md). The implementation uses integer binary64
product rounding and a private Gregorian bridge. It implements neither native
tree layout nor log/lock/network effects. Valid memory/tree frames, successful
allocation, normal helper returns and the captured floating environment remain
premises of native correspondence; the source itself performs no host float.

`InvalidTime` is a new safe refusal before mutation. `DeadlineRange` is a new
safe refusal after registration and reason insertion, preserving those changes
and the old sent flag even when already sent. Neither is claimed equivalent to
native panic/unwind state. Initial rows reject invalid timestamps and duplicate
keys; snapshots clone ordered values. Allocation failure has no rollback or
native allocator-equivalence guarantee. Pruning, reset, scheduler completeness,
outbox consumption and actual requests are outside this operation.

The source freeze and exact harness correction are separate chronological
records. [SOURCE-FREEZE](SOURCE-FREEZE.json) remains unchanged. Root and peer
review found that its original builder compared Python tuple edit pairs with
JSON list pairs, making admission fail before compilation. The static rejection
and cause are retained in [AMENDMENT](AMENDMENT.md). The corrected entrypoint
is **build-amended.py**, bound by [AMENDMENT.json](AMENDMENT.json); it compares
canonical JSON and verifies both original and amended identities. No source,
test, client, oracle, expectation or mutant definition changed. The old builder
main was never run, and there was no failed Cargo run concealed by this fix.

After the separate root/peer source/build gate, the author run completed with
exit0. [AUTHOR-QUALIFICATION](AUTHOR-QUALIFICATION.json) and the unchanged
[actual results](qualification/results.json) record:

- 174 subprocess commands:153 exit0 and21 expected exit2 transport refusals.
- 38 library tests per profile, consisting of36 unchanged baseline tests and
  two new private tests, plus eight new integration tests per profile.
- Four correct complete streams across debug/release and two distinct clean
  directories:949 histories and3776 steps per stream, all byte-exact.
- Twenty actual compiled mutants in both profiles, yielding40 complete streams.
  All18 native mutants changed native-conditional histories; both policy mutants
  changed only new-policy histories. Compilation/partial-output failure was not
  counted as a kill. Domain mismatch counts are retained in results.json.
- Ten comparator controls,20 malformed-input controls, an extra-argument refusal
  and empty-input success. The excluded evidence_contract target was not run.
- The frozen static replay passed91 negative controls and two native/corpus
  regeneration trees, with only the documented final-freeze phase marker change.

The separate [author receipt audit](AUTHOR-RESULTS-AUDIT.json) rehashed all348
child stdout/stderr references,103 unique gzip files (1,350,261 compressed bytes),
22 source copies,22 client copies and88 first-compiled artifact identities.
The114-file qualification archive preserves all112 original child receipt files
and both outer raw streams byte-for-byte. No result stream was normalized,
redacted or replaced with expectations. Original52 pre-code files and all
frozen source/harness/amendment identities remain unchanged.

Both rlibs and the release clients are byte-identical across the author's two
distinct clean directories. **Debug clients differ.** These are raw comparisons,
without masks. The record does not claim universal reproducible builds, public
availability of private compiled binaries, or hermetic OS/SDK closure. Root's
independent run/comparison is a separate review record, not an author claim here.

The corpus distinguishes934 conditional-native histories from15 new-policy
histories. Its explicit delays contain no exact multiplication-halfway input;
the universal ties-even argument comes from SOURCE-PROOF, not a claimed finite
ties-mutant kill. Multiple decoders/reviewers and mathematical checks do not
create independent runtime observations of the captured executable. It was
never executed or instruction-evaluated in this qualification.

Reproduce from the repository root with the pinned existing Rust1.94.1 toolchain,
GNU/LLVM static tools and a fresh isolated output path:

```sh
python3 -B research/work-items/RE-008-request-throttle-94/source-validation/build-amended.py \
  --toolchain <PINNED_1.94.1_TOOLCHAIN> \
  --out /tmp/hl-request-throttle-reproduce-new \
  --private-map <FRESH_PRIVATE_PATH_OUTSIDE_PACKET> \
  --source-freeze-sha 054552ab23d80266b7ed7d6d13344d7b14cff6bb239bb8b6f6a40fc9d0b0deed \
  --amendment-sha 8e197063bee646b6b65082b50bec6c531b7f76b451f142043b88aff518eafd03
```

The harness admits the full actual graph and toolchain before building copies;
it does not install anything or modify the source checkout. Exact client resource
limits, command selection, timeout/launch-error retention and exclusions are in
the frozen [VALIDATION-PLAN](VALIDATION-PLAN.md). Runtime caches are excluded from
the author distribution. Qualification is not a merge, deployment or live
consensus claim.
