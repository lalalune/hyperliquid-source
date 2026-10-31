# RE-002: keep catalogue completion bound to the four reviewed gates

- Component: repository-wide reconstruction progress tooling, bounded RE-002 supporting validation.
- Target baseline: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference can1357 pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Observation: the validator previously trusted the mutable global gate dictionary as its own schema. Adding a fifth gate to that dictionary and every component passed validation; `generate()` rendered `125% | 5/4` for a component whose five booleans were true. Removing or renaming `identity` globally and in every row also passed, weakening the documented acceptance contract.
- Fix: validate the exact canonical gate-name set (`mapped`, `built`, `behavior`, `identity`) before checking rows. Dictionary ordering and editable explanatory descriptions remain unrestricted.
- Scope: tools/catalogue.py, its existing research-tool tests, and this packet. No progress data, generated catalogue, artifact, pin or acceptance value changes.

## Reproduce

Run from the repository root with Python3.12.3 on Ubuntu24.04/WSL2:

```sh
python3 research/work-items/RE-002-four-acceptance-gates/reproduce.py
python3 -m unittest discover -s tests -p test_research_tools.py -v
make doctor
make verify test catalogue-check
```

The reproducer reads the exact base implementation with `git show`, uses the real pinned catalogue inputs, and constructs corrupted progress documents inside an automatically removed temporary directory below ignored `work/`. It renders the base catalogue to demonstrate the actual125% row, then runs the same input against the changed generator. `comparison.json` is the observed output. The copied `CONTRIBUTING.md` serves only as an existing synthetic evidence path, not a claim of reviewed reconstruction. The script performs no network or captured-binary execution. Have `work/` present before running it (`mkdir -p work`).

## Evidence and controls

Three corrupted schemas are rejected after the fix: additional gate, missing identity gate, and identity replaced with source_imported. The existing canonical schema, including reversed dictionary order, remains accepted. The focused tests failed on the base (three assertion failures across two test methods), and passed after the fix. The output comparison records the generator-level failure and before-row rather than inferring it solely from a validator test.

The task concerns JSON schema and reporting, so ELF addresses, instruction boundaries, ABI layouts, Rust builds and binary normalization are not applicable. All captured binaries remain static inputs. No reconstruction or full-component gate is requested. No inventory or literal analysis is changed; make reproduce is not required for this validator-only change.

## Results and limitations

The existing tests already check missing component records, no evidence for completed gates and impossible match denominators. This patch does not attempt semantic review of submitted evidence or prove reconstructed behavior. It enforces the fixed four-gate metric specified by docs/SCOPE.md and CONTRIBUTING.md. Related open PRs35,142,312,317 cover numeric records/duplicates or missing/malformed gate fields; none enforces the canonical gate names, and this patch does not replace those changes.

Validation results are retained in validation-summary.json. The doctor environment failure is preserved separately; no hosted CI or container success is claimed. A next review question is whether a claimed full-component evidence packet satisfies each canonical gate; that remains a maintainer decision.
