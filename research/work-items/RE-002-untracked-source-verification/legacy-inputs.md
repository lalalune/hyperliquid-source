# The preserved literal classifier needs a pinned input view

Task: RE-002 source-input membership, including the existing RE-014 literal
reproduction consumer. This extends the same PR; no additional completion gate
or independent reconstruction is claimed.

Previous source: `5bc9baff84b04c87ad9fa737d3e1711f1271eb2b`.
Reference: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
Baseline node #94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Node #115 and visor remain separate artifacts, with their manifest identities
and signatures checked by the unmodified reproduction pipeline. No addresses
or runtime behavior are inferred here.

## Observation

The earlier input fix covers catalogue and exchange consumers. The reproduction
driver still passes the complete reference directory to the imported
`tools/legacy/drift.py`. That original heuristic intentionally walks every Rust
file it receives; it does not authenticate source membership.

Make local clones of all seven pinned source repositories, retain all 37
imported files, and use the existing authenticated artifacts. Copy the real
`base/duration.rs` into a normally ignored editor history directory:
`.history/base/duration.rs`. Configure only the temporary reference's exclude
file. Its Git status stays empty and source verification passes.

| Result | Previous source | Corrected caller |
| --- | --- | --- |
| Clean source verification / reproduction | exit 0 / 0 | exit 0 / 0 |
| Ignored-history verification / reproduction | exit 0 / 1 | exit 0 / 0 |
| Clean / history literal items | 1452 / 1455 | 1452 / 1452 |
| Complete raw classifier output after history | different | unchanged |

The three added rows are duplicates under the `.history` top-level category,
not additional pinned source. The previous driver stops with "Raw classification
no longer reproduces the imported aggregate counts". Both negative results and
the temporary clone's accepted identity are retained in
`legacy-inputs-before.json`. The fixed result is `legacy-inputs-after.json`.

## Correction and boundaries

Use the existing committed-Rust selector to materialize an owned temporary
source view, retaining each selected file's relative path and exact bytes.
Pass that view to the original classifier and remove it after the child exits.
Do not modify the reference, the classifier, `grounding.py`, imported hashes,
literal overrides or canonical evidence to make a changed input pass.

The raw legacy commands remain explicit directory diagnostics. They still
include an ignored history when called directly with that directory; their
behavior is not relabeled as authenticated pinned-source analysis. The probe's
`groundingOutputUnchanged: false` is an intentional control for this preserved
raw behavior, not a failed fixed-path check.

The final three unit tests run a verbatim copy of the production reproduction
driver, the real selector and unchanged classifier. Only unrelated artifact
verification and inventory production are explicit stubs. They prove that a
committed ignored-name file remains input, ignored history does not change the
pipeline, a changed tracked literal still fails, and an unversioned directory
retains its complete input set. Before the correction: two pass and the new
pipeline regression fails. After: all three pass. These unit stubs are not the
real-source verification; the durable native probe below supplies that check.

## Reproduce

Ubuntu 24.04 / Python 3.12.3 / Git 2.43.0 / GNU Binutils 2.42. Python, Git LFS,
GPG and ripgrep must be on PATH. No captured program is executed.

```sh
python3 -m unittest discover -s tests -p test_legacy_source_membership.py -v
python3 research/work-items/RE-002-untracked-source-verification/legacy-inputs-probe.py --check
make doctor verify test catalogue-check reproduce
```

The probe runs the real artifact/inventory/reproduction pipeline twice in its
owned temporary directory. It uses local shared clones and existing artifact
bytes, with no recovery download. LFS normalization is declared only in the
probe's subprocess environment. The owned clone's LFS stat cache is refreshed
after materialization, and its staged diff must remain empty. Source inputs in
the original checkout are read only. The PR records the exact final-head check
results, optional-tool limitations and hosted CI separately.

Initial exploratory launch attempts hit Windows sandbox Git creation, a
Windows-worktree pointer passed to Linux Git, and incomplete temporary
LFS/imported-file setup. An intermediate direct edit of the legacy consumers
was rejected by the imported-file hash check and was fully reverted. Those
attempts are preserved outside the packet and are not product regression
failures or successful checks. Only the corrected, complete fixture supplies
the table above. The committed imported files are unchanged.

No Rust workspace, copied inferred implementation, private key, signing,
networked target, chain action, registration, deployment or progress gate.
