# RE-003: Require literal booleans in plan-only requests

- Component ID: cross-cutting differential harness design; no component gate requested.
- Target identities: the existing protocol accepts node #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, and visor `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Source commit: upstream `1f8c67c63ca4794c9689235471c60297f8a5c985`; pinned sources and fixtures remain unchanged.
- Claim status: observed schema-validation defect. No approval file, network service or captured executable was used in the synthetic tests.

## Reproduce and evidence

The plan-only request validator previously coerced `execute_target` and `approval_present` with `bool(...)`; values such as `1` and nonempty strings could pass as true. The protocol validator likewise accepted truthy non-boolean values for `requires_execution_approval`. The new controls fail in 34 subcases on the unmodified base. The fix requires literal booleans after the existing required-field checks and literal `True` for the protocol approval requirement. Missing-field precedence, real approval decisions, network rules and refusal to spawn targets remain unchanged.

From this worktree with Python 3.12.14:

```sh
python3 -m unittest -v tests/test_harness_boolean_fields.py tests/test_harness_plan.py
python3 tools/harness_plan.py --check
python3 tools/verify_imports.py
make doctor
make test
make catalogue-check
make verify
make reproduce
```

All 25 focused tests and the full 439-test `make test` suite pass. They cover `None`, integer and float zero/one, negative one, empty/nonempty strings, lists and dictionaries, literal boolean controls, missing fields, and CLI JSON rejection with exit status 2. Approval lookup is mocked for the new controls. Import verification, `make doctor`, catalogue check, `make verify` and `make reproduce` pass. The pinned can1357 node #94 LFS fetch was refused for lack of GitHub LFS credentials. Its pointer declared the same size and SHA-256 as the already authenticated local node #94 bytes, so those bytes were materialized locally. The submodule remains at its pinned commit with a clean index. No remote fetch was retried, and no captured binary was executed.

## Limits and next question

These tests validate request shape only. They do not authorize or run a captured target, implement a comparator, or prove isolation of a future harness. No component gate is advanced. The existing protocol and fixture identities remain the source of approved scope.

Next, review the bounded schema correction before submission.
