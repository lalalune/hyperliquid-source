# PR integration review: 1353–1895

Status: local integration and validation in progress. No component completion gate advances.

This review assembles 540 open PR heads recorded in `pr-heads.json`, preserving
all original commits. Initial main was `e5c9b6436876b2a4a39daef813171f9879317699`.
Node #94 remains bound to SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
node #115 and visor keep the separate identities in provenance/artifacts.json.

## Integration repairs

- PRs 1363 and 1381 used the same paths for distinct teardown functions.
  PR 1381 is retained under `RE-001-chain-teardown-514bf60-94` and the matching
  uniquely named tool/test. `path-collision-1381.json` records the mapping.
- Combine independent consensus and order-book exports/documentation. Generate
  the consensus Cargo lockfile from its real combined local dependency graph.
- Combine registered comparison windows, retain dependency attribution, and
  regenerate the catalogue rather than editing generated progress tables.
- Preserve every original checksum manifest affected by PR 1415 and by later
  combined-source rebinding in the two manifest JSON records. Rebinding applies
  to current tool/source references and checksum metadata, not captured node
  bytes or original instruction records. It is not a new proof of source identity.

## Completed validation

All 44 affected Cargo components pass `cargo +1.94.1 test --offline --locked`
with separate target directories (`cargo-results.json`). The combined consensus
crate and byte-progress tests also pass independently.

`raw-excerpt-audit.json` checks 27,466 instruction-byte rows across 178 newly
contributed top-level objdump excerpts directly against the authenticated
file-backed target bytes. It reports zero mismatches. This audit does not
establish function completeness, runtime behavior, or whole-component coverage.

The artifact/import/packet checks pass after the recorded checksum rebinding:
1,073 pre-audit manifests, 17,796 pre-audit resolvable entries, and 48 explicitly reported historical
rows whose payload does not exist in the committed tree. The verifier retains
its pre-existing unresolved-row limitation.

## Remaining validation

All 209 tests in 48 static validator regression modules pass after the
recorded checksum repair; the original failure and successful retry are retained
in `static-test-results.json`. Artifact hashes/signatures, import pins, catalogue consistency and full inventory/literal
reproduction pass. Additional isolated packet reproductions are running. The broad instruction-
evaluation test suite has not been run in this review. Captured executable
launches, live services, signing and chain actions have not been performed.

No integrated node build, whole-node behavioral equivalence, hosted CI success,
or new reconstruction milestone is claimed by this integration.
