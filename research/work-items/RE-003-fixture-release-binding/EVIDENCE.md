# RE-003: bind selected fixtures to the request release

- Component: offline harness planning (RE-003).
- Target release: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; separate identity controls use #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` and visor `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`; imported source is not copied or changed.
- Status: observed tooling defect, not a reconstruction or runtime vulnerability claim.
- Included: selected fixture release/digest identity checks. Excluded: target execution, networking, chain actions, comparator implementation, generated progress and captured binary interpretation.

## Reproduce

Working directory: repository root on Linux x86-64 with Python 3.12.3 and GNU Make 4.3. Materialize the already pinned artifacts/imports and references as described by CONTRIBUTING.md. No installation scripts or captured binaries are executed by this change.

```sh
python3 -m unittest discover -s tests -p test_harness_plan.py -v
make doctor
make verify test catalogue-check
```

Apply the new test methods to the baseline first and run the identical focused command: `before.log` records 20 tests with eight failing corruption cases. Then apply the five-line release comparison and repeat: `after.log` records all 20 tests passing. The existing request JSON and fixture identities are the starting inputs; tests mutate only in-memory copies. The changes include the three valid target identities as positive controls.

## Evidence

`validate_request` already requires a recognized request release and its corresponding digest, and already compares each selected fixture digest. It never compares the selected fixture's required `target_release` field. Consequently a row marked release115 or visor with the #94 digest is admitted to a #94 plan. Conversely, a #115 request accepts a row still marked #94 if its digest is replaced with #115's. Unknown/null/integer/list/object release values are also ignored. The eight before-fix failures demonstrate these exact acceptances.

The fix compares both declared identity fields before planning: fixture release must equal request release, followed by the existing digest comparison. It does not reject negative fixture records merely for being present: the committed deliberately wrong-digest fixture remains available as a negative control and still fails when selected. No fields or data of imported fixtures change. Address coordinates, disassembly, ABI, call boundaries, normalization masks and Rust build provenance are not applicable to this request planner change and are not inferred.

## Results and limitations

- Focused command: baseline eight failed cases; fixed all 20 tests pass.
- Required verification: `make verify test catalogue-check` passes, including 434 tests; see compact `validation.log` and `results.json`. Full sanitized stdout is retained locally under ignored `work/harness-fixture-release-binding/validation.full.log`, with its hash in results.json.
- `make doctor` fails on this host because git-lfs and rg are absent. `doctor.log` preserves that result; required input verification still authenticates already materialized inputs. Optional tools and exact rebuild prerequisites are also unavailable as reported. No installation or hosted CI success is claimed.
- No captured node or visor was executed. No Rust reconstruction, behavior equivalence, function coverage, full-node build, or progress gate is requested.
- Remaining gap: this is plan validation only, not a runner or an enforcement sandbox. The next task is an independently reviewed offline comparator under RE-003's stated execution-authorization boundary.

Logs replace this checkout's absolute root with `<repo>` and the home prefix with `<home>`; trailing line whitespace is removed; outcomes are otherwise retained.
