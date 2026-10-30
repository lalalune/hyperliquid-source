# bridge: explicit artifact paths must produce a report

- Task/component: `bridge`, the extra bridge area in `docs/TASKS.md`.
- Target: node **#94**, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference: can1357-hl at `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Claim: a reproduced CLI report-generation defect; no reconstruction or gate claim.

## Problem and cause

The same authenticated file succeeds with the default input or an absolute
path inside the checkout. An explicit relative path, including
`--artifact artifacts/node/94/hl-node`, fails. An absolute path to an identical
copy outside the checkout also fails. Both failures occur after the static
analysis and before the JSON report or excerpt files are written.

The report called `args.artifact.relative_to(ROOT)`. The option supplies a
`Path` without normalizing it. A relative path cannot be made relative to an
absolute root, and an external file is outside that root. `Path.relative_to`
raises `ValueError` in both cases. The file is valid; its SHA-256 check and
analysis have already succeeded.

## Fix and acceptance

Resolve the path for the report label. Use a portable repository-relative
label for files inside the checkout and the basename for external files.
The SHA-256 remains the artifact identity. An external directory, including
a workstation home path, is not included in the report. The existing digest
check, binary analysis and raw excerpts are unchanged.

Acceptance: all four path forms write their report and excerpts. The default,
relative and in-checkout absolute reports equal the retained canonical report
byte for byte. The external report differs only in `artifact`; all remaining
facts and all four raw excerpts match. A corrupt external copy must fail the
digest check and produce no output directory.

## Reproduce

Use the existing verified inputs and pinned submodules. Python 3.12.3 on
Ubuntu 24.04 is the recorded environment. This CLI needs no disassembler.

At the base, this ordinary command fails with `ValueError`:

```sh
python3 tools/bridge_inventory.py --artifact artifacts/node/94/hl-node \
  --out work/bridge-relative
```

The same command succeeds after the fix. Use a fresh output directory for each
run. From the repository root, this probe
compares the default, relative, absolute and external-copy invocations:

```sh
python3 research/work-items/bridge-artifact-paths/probe.py \
  --out work/bridge-artifact-paths
python3 -m unittest discover -s tests -p test_bridge_inventory.py -v
```

`before.json` and `after.json` retain the four outcomes, source-tool hashes,
report hashes and excerpt hashes. `before-regression.txt` retains the original
two regression failures and twelve passing controls. Checkout and temporary
input directories in failure text are replaced with explicit placeholders.
`validation.txt` records the focused checks and final verification commands.
The exact tested commit and full-suite results are recorded in the PR; the
tool hash binds this packet without a self-referential commit hash.

The canonical default report SHA-256 remains
`c228730b649ad1b2b9f967a8960229c3680e266128b3ee01b5d470a5954e3016`.
All binary addresses and coordinate systems remain in the original
[`bridge` packet](../bridge/README.md); this change does not reinterpret them.

## Limitations and next step

This is an offline tooling fix. It does not execute the captured node or visor,
perform signing, contact a chain, recover Rust implementation, establish
behavioral equivalence, or change any progress gate. External files with the
same basename are distinguished by the verified SHA-256, not by a private
filesystem path. Hosted CI and maintainer acceptance remain separate results.

The next step is maintainer review of the reproduced CLI fix and its unchanged
analysis evidence.
