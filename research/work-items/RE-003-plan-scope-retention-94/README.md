# RE-003: Preserve the declared research scope in a harness plan

- Component ID: cross-cutting harness; no component gate requested.
- Target release: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base source commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference source: none used; no inferred or imported implementation copied.
- Claim: observed offline planner output defect and correction, not target behavior.
- Bounded question: does a published plan retain the required component and
  bounded question from the request that it validated?

## Evidence

`AGENTS.md` requires a component and bounded question for each task. The RE-003
protocol makes `component_id` and `bounded_question` required request fields.
`validate_request()` checks their presence, but its returned plan omitted both.
Changing either field in the committed valid plan-only example therefore
produced byte-identical CLI output. A saved plan could not describe which
declared research scope it represented without the original request document.

The correction copies those two fields into the returned plan. It changes no
request validation, approval, network or execution rule. Binary addresses and
function boundaries are not applicable to this tooling defect; no node bytes
were read or executed by this probe.

`before.json` and `after.json` retain actual CLI results from the same six
requests using Python 3.12.14. `inputs.json` binds the two planner versions,
the unchanged existing design packet and the retained evidence. The explicit
denominator is six CLI cases, not target functions or reconstructed behavior:

| Cases | Base | Fixed |
| --- | --- | --- |
| Original valid request | planned; component/question omitted | planned; scope retained |
| Only component changes | output equals original | component change visible |
| Only bounded question changes | output equals original | question change visible |
| Existing execution, network and wrong-digest rejection examples | all three exit 2 | identical rejections, all three exit 2 |

`comparison.json` records that the request hashes match, the original plan
fields are unchanged, the only added fields are the two scope fields, and
all three rejection results remain identical.

## Reproduce

From a checkout containing this packet, run against each existing planner
checkout. The probe writes temporary request JSON under `TMPDIR`, invokes only
the Python plan validator, and prints its result. It performs no networking,
signing, chain action, captured-binary access or target execution.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/work-items/RE-003-plan-scope-retention-94/probe.py \
  --planner /path/to/base/tools/harness_plan.py > work/scope-before.json
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/work-items/RE-003-plan-scope-retention-94/probe.py \
  --planner tools/harness_plan.py > work/scope-after.json
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s tests -p test_harness_plan.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -B -O -m unittest discover \
  -s tests -p test_harness_plan.py -v
make doctor verify test catalogue-check
```

Use the stated base commit for the first planner. The three new real CLI
regressions fail on the unchanged planner; after the fix all 20 harness tests
pass normally and under `-O`. The clean base's full required checks passed
431 tests. The PR records the final tested commit and observed full checks.
`make reproduce` is not applicable: no inventory, literal analysis or binary
evidence interpretation changes.

## Results and limits

This is independently authored offline tooling. It preserves the request's
declared labels; it does not validate their semantics or establish fixture
suitability for a component. The existing synthetic fixtures remain placeholders.
No comparator, Rust component build, target execution, native reconstruction,
behavior/identity acceptance or progress-gate change is claimed. All pins,
captures, imported source and generated progress tables remain unchanged.

The next harness question remains the design packet's existing one: obtain a
reviewed target-grounded expectation and comparator before claiming behavior.
