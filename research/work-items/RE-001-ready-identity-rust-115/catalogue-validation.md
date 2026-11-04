# Post-index catalogue correction

The earlier successful catalogue check ran before the new files were indexed.
The generator counts tracked Rust areas/manifests/work-item directories using
git ls-files, so that check missed the newly added inventory. After the source
commit 05c7075fd7690f6937e09dd7345eca40697f6470, the same check correctly failed with stale README.
This is a real contribution metadata defect, not an environment prerequisite.

Regenerated README.md and docs/assets/research-progress.svg with the repository
generator after indexing the new contribution. Post-index catalogue --check
now passes. No component gate, registered byte window, imported input or pin
changes. All pre-existing contribution source, tests, native/own exports,
compiler/model hashes and comparison records remain byte-identical to that
full-suite-validated source commit. Only generated inventory documentation,
this correction note and the packet manifest change afterward; the complete
suite is not rerun for these documentation-only changes. Its observed results
and failures remain historical, not restamped as a fresh full-suite success.

Reproduce: python tools/catalogue.py; python tools/catalogue.py --check, after
the contribution files are tracked/indexed. This packet manifest is checked
from repository root. Hosted CI results are not asserted by this note.
