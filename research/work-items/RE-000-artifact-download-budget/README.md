# RE-000: Bound artifact recovery writes by the manifest size

- Component ID: cross-cutting artifact provenance tooling; no component gate requested.
- Target identities: node #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, and visor `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31` from `provenance/artifacts.json`.
- Source commit: upstream `1f8c67c63ca4794c9689235471c60297f8a5c985`; pinned source revisions remain unchanged.
- Claim status: observed tooling defect and bounded fix. No captured executable was run.

## Reproduce and evidence

`fetch_one` previously wrote every response chunk before checking the final file size. Three synthetic overflow controls fail against the unmodified base: a first chunk over budget, a valid prefix followed by one extra byte, and a nonempty response for a zero-byte budget. The response mock records writes and rejects reads after the overflowing chunk. The fix checks the remaining manifest-declared byte budget before each write while retaining the fixed 1 MiB read size, final size/SHA-256 check, atomic replacement, and temporary-file cleanup.

From this worktree with Python 3.12.14:

```sh
python3 -m unittest -v tests/test_artifacts.py tests/test_artifact_download_budget.py
make doctor
python3 tools/verify_imports.py
make test
make catalogue-check
make verify
make reproduce
```

The focused suite passes 14/14 tests, including zero-byte, irregular-chunk, short-body, wrong-hash, and existing-target controls. `make test` passes 439/439 tests. `make doctor`, import verification, catalogue check, `make verify`, and `make reproduce` pass. The pinned can1357 node #94 LFS fetch was refused for lack of GitHub LFS credentials. The submodule LFS pointer declared the same size and SHA-256 as the already authenticated local node #94 bytes, so those bytes were materialized locally. The submodule remains at its pinned commit with a clean index. No remote fetch was retried, and no captured binary was executed.

## Limits and next question

The guard caps bytes written to the temporary file by the manifest-declared size. It does not bound network transfer or response time, and it does not turn the manifest size into a signed property. Synthetic HTTP chunks prove the guard without depending on a live recovery server. No Rust implementation or target-equivalence claim is made; progress gates remain unchanged.

Next, review the bounded change and its synthetic controls before submission.
