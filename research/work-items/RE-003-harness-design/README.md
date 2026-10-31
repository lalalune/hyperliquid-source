# RE-003: Isolated offline differential harness design

- Component ID: cross-cutting (harness); no component gate requested
- Target release and full SHA-256: protocol binds requests to one of
  node #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  or visor `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`
- Source commit / reference commit: design against repository tip; no can1357 copy
- Claim status: observation (design packet)
- Scope included and excluded: see `protocol.json`

## Reproduce

```sh
python3 tools/harness_plan.py --check
python3 tools/harness_plan.py --request research/work-items/RE-003-harness-design/examples/deny-execute.json
python3 -m unittest tests.test_harness_plan
```

No captured binary is read or executed by these commands. Tool versions: Python 3.
Declared side effects: none (plan and validate only).

## Evidence

Acceptance from `docs/TASKS.md` for RE-003:

1. Isolated offline differential protocol — `protocol.json` plus this README.
2. No-network / side-effect controls — fail-closed defaults in `protocol.json`
   (`network: deny`, `execution_default: denied`) and enforced by
   `tools/harness_plan.py`.
3. Fixture identities — `fixture-identities.json` with digest, payload hash,
   declared effects, and positive/negative labels.
4. Positive and negative controls — named in `protocol.json` and covered by
   unit tests.
5. Obtain execution approval before running target — any request with
   `execute_target: true` is rejected unless
   `research/work-items/RE-003-harness-design/APPROVAL.md` exists for that
   exact `request_id`. This packet does **not** include APPROVAL.md.

## Implementation and comparison

Not yet implemented. This packet does not ship a comparator, does not run
hl-node or hl-visor, and does not request mapped/built/behavior/identity gates.

`tools/harness_plan.py` is plan-only, matching the `ghidra_plan.py` pattern:
validate a request, print the plan, refuse execution.

## Results and limitations

- Design checklist in `protocol.json` is satisfied by the files in this directory
  and by the unit tests.
- The positive fixture binds a real expectation blob: the 89-byte
  recursive-packer window measured by RE-001
  (`research/work-items/RE-001-short-string-94`, fixture
  `94-pos-equal-window-v1`). The negative controls remain synthetic templates.
  Broader real-fixture coverage waits on later component packets.
- Container isolation recommendation points at `.devcontainer/Dockerfile`;
  the container build itself is not verified here.
- Next question: implement the comparator behind the same approval gate.
  The synthetic positive fixture has been replaced with one digest-bound
  RE-001 expectation.
