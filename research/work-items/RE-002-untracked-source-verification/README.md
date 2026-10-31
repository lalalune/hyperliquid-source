# RE-002: verification and analysis bound to pinned source inputs

- Component: build provenance and pinned analysis inputs. No progress gate requested.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Baseline node #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- This is a tooling observation. The reproduction uses a synthetic temporary Git
  source repository; it neither modifies imported references nor executes a target.

## Problem and cause

`make verify` promises to reject modified pinned source repositories. With Git's
`status.showUntrackedFiles=no`, an extra source file does not appear in
`git status --porcelain`. The verifier used that output and printed that all
pinned source repositories were verified. Before the input-selection correction, the source walker in
`tools/catalogue.py` reads `reference.rglob('*.rs')`, which includes the
extra file. A correct HEAD alone does not establish the analysis input tree.

This is an ordinary Git display setting, set only in the temporary fixture for
the reproduction. No malformed manifest or binary is needed.

The tracked-file case has the same problem even with `--untracked-files=all`:
`git update-index --assume-unchanged retained.rs` or `--skip-worktree` hides
later edits from status. The catalogue still reads the modified file. The first
implementation at `f28abf72b3a896e37fec044fd9d7191f11f8a7c5` accepts both
modified fixtures while reporting a clean source pin. This extension stays in
the same contribution instead of splitting one status-trust defect into PRs.

## Reproduce

From the repository root, with Python and Git on PATH:

```sh
python3 research/work-items/RE-002-untracked-source-verification/reproduce.py --check
python3 -m unittest discover -s tests -p 'test_verify_imports.py' -v
python3 research/work-items/RE-002-untracked-source-verification/index-flags-probe.py --check
```

The probe can check another checkout with `--repository-root /path/to/checkout`.
It commits one synthetic retained file, then adds one untracked `.rs` file. The
same tree is checked with normal and hidden-untracked status settings. Only the
temporary repository's Git configuration changes.

Before the fix, the probe reports clean=true, extra/normal=false and
extra/hidden=true; `--check` exits 1. After the fix the values are true, false,
false and the check exits 0. Ordinary status remains empty in the hidden case;
an explicit `--untracked-files=all` lists `?? unexpected.rs`. Both source files
remain visible to the glob. The regression also checks the clean tree under the
hidden setting, so the fix cannot simply reject that setting.

`before.json` and `after.json` preserve these probe outputs. They agree across
Windows Python 3.10.11 / Git 2.51.1.windows.1 and Ubuntu Python 3.12.3 / Git 2.43.0.
`MANIFEST.sha256` binds this packet's bytes. The Linux regression on the original
tool has five passes and the one expected new failure, with no test errors.

The index-flags probe checks a clean and edited tracked file for each flag.
`index-flags-before.json` preserves the result on the first implementation:
both clean and modified source are accepted. `index-flags-after.json` shows
that clean source is accepted and modified source is refused. Status still
prints nothing in all four cases. The probe confirms that the user's index
bytes and flags survive each check. The new regressions additionally reject
deleted tracked source and allow the restored original bytes. On the first
implementation, six focused tests pass and these two new regressions fail;
the corrected focused suite has eight passes and no errors or failures.

## Fix and limits

Request `--untracked-files=all` and keep the existing commit, staged/tracked
change, imported-file digest and failure checks. Also read HEAD into a fresh
temporary index and compare the actual working tree against it. This index has
none of the user's assume-unchanged or skip-worktree flags or cached file stats.
Git still applies its normal content normalization, including LFS. The temporary
index stays outside the source repository; split-index and ignorestat are
disabled only for those commands, and read-tree bypasses sparse filtering.
Disable optional index writes for the status reads, preserving the user's real
index and configuration. Never clear their flags or refresh their index in place.

Ignored-file acceptance is preserved. The input-selection extension below
keeps those files out of canonical analysis without changing any artifact,
inferred source, clean inventory output, Rust reconstruction or acceptance gate. Machine-code addresses and new runtime-equivalence measurements are not
applicable. Existing artifact, signature, pin, catalogue and reproduction checks
remain the validation of those separate inputs.

Windows Python 3.10 reproduces the new failure. The original test file also
encounters an unrelated Windows `WinError 5` while its existing test removes
read-only Git objects with `shutil.rmtree`. Preserve that failed run; use the
existing Ubuntu validation environment for the complete required checks.

The index-flags extension is reproduced with Ubuntu 24.04, Python 3.12.3 and
Git 2.43.0. Its native Windows execution is not claimed. Run `make doctor`,
`make verify test catalogue-check reproduce` at the submitted commit; the PR
records their exact-head results separately from the earlier six-test run.

Next step: maintainers review this verification change separately from open
manifest-key validation (#115) and retained-import coverage (#190).


## Ignored local inputs

[The input-selection extension](ignored-inputs.md) preserves the reproduced
237-to-239 reference count and 209-to-290 address-survey contamination from two
ignored local backups. Both consumers now select committed Rust paths. The
before/after JSON and reusable `ignored-inputs-probe.py --check` preserve this
additional source-input failure and its correction in the same packet.

The [legacy reproduction caller](legacy-inputs.md) is covered by the same
membership rule. Its original imported classifier remains unchanged; an
ignored editor history no longer causes a false canonical reproduction
failure. The new probe preserves the actual 1452-to-1455 before result and
checks the complete pipeline on all real pinned inputs.
