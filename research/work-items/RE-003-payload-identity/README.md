# RE-003: reject malformed declared payload hashes

This is a bounded offline planner-admission correction, not a reconstructed
component or an execution harness. Base:
`1f8c67c63ca4794c9689235471c60297f8a5c985`. The actual committed design packet
declares node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured artifact was read or executed for these checks; no address or
function-boundary claim is made.

## Contract and defect

The existing RE-003 protocol includes “Synthetic fixture identities with
explicit SHA-256 and declared side effects” and requires `payload_sha256`.
The design README likewise names a payload hash as fixture-identity evidence.
Its empty-payload placeholders contain the valid SHA-256 of empty bytes.

`validate_fixtures()` checked the target hash format but only required the
payload-hash field to exist. In private copies of the committed protocol,
fixture identities and request, replacing only the selected positive
fixture's payload hash with `not-a-sha256` still made both `--check` and
`--request` exit 0. They reported `protocol: ok` and `status: planned`.

The correction requires that declared payload hash to be a string with
64 lowercase hexadecimal characters, consistent with the existing target-hash
representation. It does not read a payload, claim a matching preimage, or
alter the parser, approval gate, committed fixtures or protocol.

## Validation

Python 3.12.14, standard library only. Run from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_harness_fixture_identity.py
PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_harness_plan.py
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/harness_plan.py --check
```

The new three-method regression had four failures on the base: malformed
text, non-hexadecimal text, a non-string value and the actual malformed CLI
request were accepted. All three methods pass after the fix, as do the
17 existing harness tests. The CLI test copies the real source/design packet
into a private directory and changes only the selected payload-hash value;
no parser, approval check, target or comparator is mocked.

The same private-copy CLI method before/after additionally confirms:

- Clean `--check` and `--request` both exit 0, with byte-identical output.
- The malformed copy now rejects both entrypoints with
  `invalid payload_sha256` and publishes no plan. Exit 1 follows the existing
  packet-validation error path; this does not introduce a new error protocol.
- The intentionally wrong-target fixture remains loadable as a negative
  control and still rejects its selection with exit 2.

`results.json` binds exact source hashes, method and raw-output receipt hashes,
test results and limits. All original design-packet bytes remain unchanged.
No full-suite, hosted CI or container claim follows from these focused checks;
common repository gates are coordinated separately.

## Limits and ownership

This checks declared hash syntax only. Actual payload/content binding,
comparators, no-network runtime isolation and target execution remain future
separately approved work. The synthetic placeholders are not target-derived
expectations. No Rust build, target behavior, byte equivalence, security or
component milestone is claimed; all progress gates remain unchanged.

Open #151 owns duplicate-key parsing in `load_json`; open #64 owns
`approval_covers` matching. Neither function is changed here. No unlicensed
inferred reference source is copied.
