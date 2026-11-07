# Validation

Source baseline `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; static Windows
x86-64 host; Python 3.12.14, Capstone 5.0.6 and pyelftools 0.32.

| Check | Actual scope/result |
| --- | --- |
| scoped `verify.py --write` | passes: authenticated full target digest, two exact FDE-described extents, 519 bytes / 142 decoded instructions |
| ordinary scoped `verify.py` | requires exact byte regeneration of both exports; final run reported in PR description |
| operative instruction mutations | 13/13 rejected with whole-file authentication disabled only for the controls |
| finite scalar boundary corpus | 360 combinations, zero disagreement; same-author formulas, normal returns and stable TLS assumed; external helper writes excluded |
| current artifact verifier | all six pinned size/SHA-256 entries match; signature stage fails because GPG is not found through this host's default executable search |
| doctor | analysis readiness false: native binutils, GPG, Ghidra and Rust toolchains not on the selected PATH; no target executed |
| initial baseline packet-manifest sweep | fails on an existing archive still materialized as a Git LFS pointer; LFS materialization requested before the final sweep |
| manifest sweep after LFS materialization | passes: 1,754 manifests, 20,512 entries; the existing checker reports 65 grandfathered rows with no committed payload |
| `python -X utf8 tools/catalogue.py` | passes with this packet staged in an isolated index; only the generated README/SVG work-item inventory changes |

The focused verifier does not require a compiler or a running target. Its FDE
parser comes from this exact baseline. The raw call records preserve external
boundaries rather than simulating or naming the callees. An LSDA address is
recorded, but its dispatch/action table is not qualified.

The complete repository test suite and original-binary inventory reproduction
are not claimed to pass. Checks of every unrelated reconstruction would require
their native toolchains and other baseline prerequisites; the PR description
records the actual repository-level results. There is no reconstructed Rust,
runtime or concurrent equivalence, hosted CI pass, component gate change or
registered byte-coverage increase in this contribution.
