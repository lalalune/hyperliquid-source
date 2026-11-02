# PR integration review

Status: integrated locally; full test inventory and follow-up validation complete. No component completion gate advances.

This packet began with 540 PRs (#1353–#1895). `pr-heads.json` preserves that
snapshot; `followup-pr-heads.json` records subsequent heads, including amended
#1889 and #1895. All original commits remain parents of the integration history.
Initial main was `e5c9b6436876b2a4a39daef813171f9879317699`.
Node #94 remains bound to SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
node #115 and visor retain their separate identities in provenance/artifacts.json.

## Integration repairs

- PRs #1363 and #1381 used the same paths for distinct teardown functions.
  Retain #1381 under `RE-001-chain-teardown-514bf60-94` and a uniquely named tool/test.
  `path-collision-1381.json` records the mapping.
- Combine independent consensus and order-book exports/documentation. Generate
  the consensus Cargo lockfile from its real combined local dependency graph.
- Combine registered comparison windows, retain dependency attribution, and
  regenerate the catalogue rather than editing generated progress tables.
- Preserve original manifests affected by combined-source checksum rebinding.
  Rebinding applies to current source/tool references, not captured target bytes.
  The original and follow-up manifest records retain old and new hashes.
- Rebind the cumulative-minute packet to the GPG-diagnostic-only helper change;
  its complete static verifier and negative controls pass with Apple LLVM.
- Permit only input-label and implicit DS/ES display differences for exact
  F3 48 A5/AB instructions in four excerpt verifiers. Original verifiers and
  manifests are retained. Twenty-four positive/negative display checks pass.
- Correct the ABCI state-link README's stale verifier hash.
- Use a wide intermediate for WAL rel32 sign extension: NumPy 2 otherwise
  rejects subtracting 2**32 from the int32 array and blocks the binary census.
  All 27 replay-driver tests pass; the original verifier/manifest are retained.
- Check ChaCha verifier imports independently of manifest path strings. The
  former substring check rejected a legitimate bound-tool filename; exact
  permitted imports remain checked. Original test/manifest and retry are retained.

## Validation

The first snapshot passed all 48 affected Cargo components with Rust 1.94.1,
offline and locked dependencies. Follow-up bincode and consensus tests pass;
TCP frame tests pass in debug and release with all features. Thirty additional
standalone Rust qualification harnesses pass with the installed pinned rustc.
Their documented standalone scope does not imply a recovered whole-node graph.

All 209 tests across 48 static-validator modules and 24 display-comparison tests
pass. `raw-excerpt-audit.json` directly checks 27,466 instruction-byte rows in
178 contributed top-level objdump excerpts against authenticated target bytes,
with zero mismatches. This is not a function-completeness or runtime claim.

Artifact hashes/signatures, 38 imported files, submodule pins, catalogue
consistency and inventory/literal reproduction pass. The packet verifier
explicitly retains 48 grandfathered rows whose referenced historical files are
absent; this existing limitation is not silently converted into evidence.

`test-review.json` records the broad isolated unittest inventory, completion
state, original failures and replacements by focused reruns. Early runner
import failures were repaired in the external runner. Unwind-index tests use
the digest-matched local index. Python bytecode writes are disabled so importing
archived compiler inputs cannot add undeclared files to a frozen snapshot.
The user authorized bounded offline instruction evaluation on synthetic local
fixtures. No full captured node/visor executable, live service, signing key,
public-network fixture or chain action was used.

## Reproduction limits

The additional packet replay records retain original successes and failures.
Twenty strict scripts require GNU 2.42, which is unavailable here. Independent
bindings/relations and available-provider checks are reported separately.
Historical pre-source packets were replayed in their original source contexts;
the fixed20 current-source build and source freeze are retained separately.
Provider-only comparisons require all non-provider fields and exports to match.
For the RPC lookup packet, GNU 2.44 versus 2.47 changes the recorded provider
version: the strict retained-record test therefore fails, while all eight
non-provider exports match and all 27 corruption controls pass with the current
provider. The original receipt and strict verifier remain intact.

No integrated node build, whole-node behavioral equivalence, hosted CI success,
or new reconstruction milestone is claimed by this merge review.

The full initial 1,307-module unittest inventory completed. Function-style
tests were run with pytest. Four strict current-tree reproduction checks remain
non-green: the RPC provider-version check described above, both n21 historical
source-snapshot checks, and the nonce-ring historical checker-hash check. The
three historical tests pass at their original PR heads (#1524 and #1694), while
the combined source components pass their separate Cargo checks. These results
do not turn the strict current-tree tests into passing checks. See
`historical-test-replays.json`, `test-review.json`, and the provider control record.
