# RE-001: node #115 progress evidence review, 2026-11-09

This reviews the README's accounting after the first reviewed PR batch reached `main`, and before the remaining integration was accepted. It authenticates the selected compiled-code comparison registry and checks the printed fractions against their denominators. It does not accept a whole-component reconstruction gate.

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes). Addresses are ELF virtual addresses. The executable `.text` denominator is 83,719,936 bytes.

## Observed source snapshots

- `main`: `d6395549bfdcfb2237a9ce2129253fd255244eb7`, the merge of PR #5984; tree content equals `b341450e887535e37db1970e043f0378e1f0c317`.
- Pending integration: `91b28122e3956cef666750dc579d5f77810cdfef`, tree `146c7d6fa7960c33c0540f0c5070aa88fed049d2`. This is a review snapshot, not a claim that the remaining source heads were already merged.

| Measure | Observed main | Pending snapshot |
| --- | ---: | ---: |
| Rust implementation areas | 100 | 216 |
| Top-level Cargo manifests | 63 | 179 |
| Research work items | 3,240 | 3,702 |
| Components registering bounded Rust paths | 14/23 | 20/23 |
| Registered bounded paths | 66 | 88 |
| Accepted full-scope gates | 0/92 (0.00%) | 0/92 (0.00%) |
| Complete components | 0/23 (0.00%) | 0/23 (0.00%) |
| Compared `.text` bytes | 5,313,802/83,719,936 (6.34712%) | 5,318,174/83,719,936 (6.35234%) |
| Raw-equal `.text` positions | 4,964,007/83,719,936 (5.92930%) | 4,968,370/83,719,936 (5.93451%) |
| Raw-equal comparison windows | 507/7,884 | 507/7,885 |
| Raw + relocation-qualified windows | 7,884/7,884 | 7,885/7,885 |

The final README must be regenerated from the actual integrated source tree. This evidence packet itself adds one research work item, and later accepted work can change inventory counts without changing acceptance percentages.

## Independent checks and result

`verify.py` uses its own ELF64 section parser, tracked Git paths and direct source/target byte comparison; it does not import the production catalogue or byte-progress comparator. It verifies the full target digest, all 19/22 registry-pinned evidence files, every complete target/source body hash, disjoint selected target intervals, relocation record ownership and bounded displacement masks. The two unequal-extent candidates retain zero aligned-byte credit. It recomputes the inventory, eight completion/byte-fraction rows and eight binary-comparison rows in each observed README. Four negative controls reject an unmasked byte change, an out-of-bounds mask, an unsupported relocation type and overlapping masks; the valid masked-difference control passes.

The pending increase is one 4,372-byte **public BLST dependency** window from PR #5589. It adds 4,363 raw-equal byte positions; the other nine differing positions lie in twelve recorded relocation bytes. All 4,360 unmasked positions match. The new comparison is relocation-qualified and is not raw-equal. Original symbol/build producer identity remains unresolved; the selected source is identical in the credited public BLST versions.

Every registered aligned comparison in both snapshots is attributed to an existing open-source dependency. No first-party component comparison bytes are registered. This does not mean zero correct first-party code: independently authored, bounded Rust fragments exist and are recorded separately.

## Gate-status assessment

The scope still has 23 components and four gates per component: full mapping, pinned source build, target-grounded behavior and code/data identity. `evidence.json` records each component's declared scope, registered bounded paths, gate state, accepted evidence and whole-component function denominator. All 92 gates remain false, all full-component function denominators remain unmeasured, and no accepted gate evidence is registered. Individual builds, bounded semantic cases and dependency byte windows do not close those full scopes.

The source-built-node requirements remain open: a complete first-party and private-fork dependency graph, integrated executable, complete code/data/call/relocation closure, state synchronization and validation, restart persistence and required APIs. No engineering-effort completion percentage can be inferred from the PR count or the available fragments. Updating `reviewed_on` records this status review; it does not accept a new component gate.

## Reproduce

Materialize the authenticated inputs and a separate hydrated source tree at the pending snapshot, then run `make catalogue` in that tree. From a repository containing the pinned commits:

```sh
python3 research/work-items/RE-001-node115-progress-review-2026-11-09/verify.py \
  --repo . --provider /path/to/hydrated-91b28122-tree \
  --out work/progress-review-recheck.json
make catalogue
make catalogue-check
```

The verifier's default `--before` and `--after` are the immutable commits above; it refuses mutable ref names. `evidence.json` includes the Python/Git versions, auditor source hash, both source trees, all calculated fractions and control results. Exact evidence re-creation requires those source/provider snapshots; a later tree must receive its own refreshed inventory.

Limits: this is static accounting, not native target execution or a hardware/whole-node equivalence proof. Recorded relocation masks do not establish helper semantics, call-target closure or complete program data identity. No captured code is executed, and no live Hyperliquid network traffic, private key or chain action is used. Next step: continue the bounded startup, transport, storage/bootstrap and state-validation work until a complete component scope can satisfy its original gates.


## Post-merge refresh

The earlier review above and its `evidence.json` / `verify.py` are preserved.
This additional snapshot records the actual merged `main` at
`0e70dfafd1ae86649a1660405b9110dbebe93050`, tree
`1ff44e49fab7e702781c35a5c87fa2affd59cae6`, before this documentation refresh.
It replaces neither historical snapshot nor their original negative results.

| Measure | Merged-main snapshot |
| --- | ---: |
| Rust implementation areas | 216 |
| Top-level Cargo manifests | 179 |
| Research work items | 3,705 |
| Components registering bounded Rust paths | 20/23 |
| Registered bounded paths | 88 |
| Accepted full-scope gates | 0/92 (0.00%) |
| Complete components | 0/23 (0.00%) |
| Fully mapped / built / behavior-validated / code-data-identical components | 0/23 each (0.00%) |
| Compared `.text` bytes | 5,318,174/83,719,936 (6.35234%) |
| Raw-equal `.text` positions | 4,968,370/83,719,936 (5.93451%) |
| Raw-equal comparison windows | 507/7,885 (6.43%) |
| Raw + relocation-qualified windows | 7,885/7,885 (100.00%) |

All 22 registry-pinned evidence files and complete source/target body hashes
were authenticated again. The 7,885 aligned windows have disjoint target
intervals; all are public-dependency comparisons, with 4,968,370/5,318,174 raw
matching positions (93.42%). Two further socket2 candidates retain unequal
227-byte target / 418-byte source extents and receive no aligned-byte credit.
The positive relocation-mask control passes and all four original corruption
controls remain detected. No captured code is executed.

Compared with the old pending snapshot, only the research-work-item inventory
increases by three; the Rust-area and manifest counts, byte totals and accepted
gates are unchanged. Appending this section to the existing packet adds no
work item. The README's generated figures already match the merged tree;
this refresh pins their post-merge evidence instead of claiming more completion.
The source-built executable, complete component scopes, code/data/call closure,
whole-ELF identity and end-to-end acceptance remain open.

`post-merge-evidence.json` records the independent recount, per-component gate
assessment, owning-source hashes and preserved unmatched candidates.
`post-merge-verify.py` reuses only the SHA-bound historical independent auditor,
not the production catalogue comparator. Its full README hash is deliberately
of the pinned Git snapshot. On a refreshed checkout it checks that the generated
README block still matches, while allowing this explanatory prose to be added
outside the markers. This avoids a self-referential evidence hash.

From a hydrated checkout containing the pinned commit:

```sh
python3 research/work-items/RE-001-node115-progress-review-2026-11-09/post-merge-verify.py \
  --repo . --provider . \
  --check research/work-items/RE-001-node115-progress-review-2026-11-09/post-merge-evidence.json
make catalogue-check
```

To write a fresh comparison file, replace `--check` with
`--out work/post-merge-progress-recheck.json`. The evidence preserves the runtime
versions originally observed; check mode permits a different Python/Git version
while requiring every numerical result, source binding and control to match.
