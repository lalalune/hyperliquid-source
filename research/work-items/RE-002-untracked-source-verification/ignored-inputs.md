# RE-002: ignored files must not enter pinned-source analysis

## Question and scope

Can ignored local Rust backups alter outputs after the complete imported-file
and source-pin verifier accepts the input view? This extends the same source
input correctness contribution; it does not create a new reconstruction claim.

- Node #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Before tool revision: `7b446664985a8ef8f9a5e67e5905a210e1b908d5`.
- Components: RE-002 pinned inputs; consumers are catalogue metadata and the
  RE-010 exchange address survey. All acceptance gates remain unchanged.

## Observation and reproduction

`ignored-inputs-probe.py` creates owned temporary local clones of all seven
pinned sources. It reads the actual 37 retained imported inputs and authenticated
node94 file. A test-local exclude rule ignores `*.backup.rs`. Two copies stay
only in that temporary reference: `base/local.backup.rs` and
`l1/exchange/local.backup.rs`. No original imported reference or user config is
modified; Git never contacts a remote. No captured target is executed.

The verifier accepts both the clean and ignored-backup views. This acceptance
is retained: ignored local files are not newly forbidden. Before the correction,
the catalogue and address survey still walk every disk `.rs` file and include
both backups as if they were pinned reference content.

| Observation | Before | After |
| --- | --- | --- |
| Imported/source verification | 37 inputs / 7 pins accepted | same |
| Normal Git status with ignored backups | empty | empty |
| Catalogue reference files, clean / backups | 237 / 239 | 237 / 237 |
| Exchange address rows, clean / backups | 209 / 290 | 209 / 209 |
| Complete generated catalogue bytes | changed | unchanged |
| Ordinary untracked source / tracked edit | rejected / rejected | same |

The original observations are preserved in `ignored-inputs-before.json`.
The corrected output is `ignored-inputs-after.json`.

```sh
python3 research/work-items/RE-002-untracked-source-verification/ignored-inputs-probe.py --check
python3 -m unittest discover -s tests -p test_pinned_source_walk.py -v
```

The focused tests use real Git plus independently authored comment fixtures;
they do not copy inferred Rust into implementation. On the previous tool code,
the catalogue and address-survey regressions fail while the existing unversioned
diagnostic view succeeds: one passed, two failed, no errors/skips. After the
correction all three pass. A file deliberately committed despite its ignore
pattern remains an analysis input, so simply discarding every ignored-name
pattern would not satisfy the regression.

## Correction, overlap and limits

One shared source iterator intersects the existing walk with the committed Git
tree when a Git source repository is present. It reads `HEAD` directly, avoiding
index flags and ignore-dependent membership; no config/index writes are made.
Both affected consumers use it. Explicit unversioned diagnostic views retain
their previous behavior and do not gain a provenance claim. Existing verification
still rejects wrong commits, modified tracked bytes and ordinary extra sources.

Open #104 addresses native path spelling; this change preserves each caller's
path rendering and changes membership only. #138 concerns output encoding;
#60 the target digest; #190 retained-import coverage. No part of those changes
is claimed here. The source-path iterator line also changes in #104 and needs
normal merge composition, not a separate duplicate fix.

Clean canonical catalogue and dispatch outputs remain byte-identical. No
generated progress table, scope, component gate, imported evidence, source pin,
Rust workspace, target binary, signing/key/network operation or deployment is
changed. Python 3.12.3 / Git 2.43.0 on Ubuntu 24.04; Windows execution of this
extension is not claimed. Optional Ghidra/Rust/runtime equivalence remains
unverified. Exact final-head required-check results belong in the PR.
