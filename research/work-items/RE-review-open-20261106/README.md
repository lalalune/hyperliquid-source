# Node #115 open-PR integration validation

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The completed review integrates 1,204 PR heads and closes 41 out-of-scope
PRs. No reviewed PR remains held for evidence or execution approval. Exact
heads and validation receipts are in `reviewed-pr-heads.json` and
`validation.json`. Reconstruction remains incomplete; no component gate is
advanced and no full-node or whole-ELF equivalence is claimed.

All 1,051 current test files have passing source-hash-bound receipts. The
final combined branch reran 81 added, previously deferred or changed files,
the Linux-only snippet suite, and all 73 repaired prior-corpus checkers.
The 57 previously held differential suites and 23 baseline suites ran under
explicit user authorization. The native snippet suite passed seven checks,
including its 20,000-case comparison, in an offline Linux amd64 guest on a
macOS arm64 host. No full captured node/visor process, networking or signing
was performed. `execution-validation.json` records the scope and environment.

The original review passed 616 selected packet verifiers, 38 top-level Cargo
components and two retained flat Rust libraries. All 21 additional Rust
implementations pass their sealed-stream comparison builders and compiled
negative controls using rustc 1.94.1 in a separate source mirror. Five older
nested helper checks lacked standalone lockfiles; those original failures
remain recorded and their parent builds passed.

`make doctor verify catalogue-check reproduce` passes. The original batch
byte audit checked 550,472 recorded instruction rows; the follow-up batch
checks 35,972 rows, with zero mismatches. These overlapping recorded-row
counts are not function coverage or a whole-node denominator. No hosted CI
success is asserted. Raw exports, original negative results and detailed
logs remain retained, with log hashes in the receipts.

## Review corrections

`metadata-repairs.json` and `review-corrections.json` retain the manifest,
packed-lane, module-collision, path and renderer corrections. Original
submitted manifests and affected historical documents remain byte-for-byte.
PR #2721 retains its already documented D window as reused context, earning
no additional coverage credit; its 14 focused checks passed.

The 73 static comparison PRs use an authenticated frozen manifest of 1,211
public record inputs. Earlier private-worktree counts remain historical,
not reproduced evidence or coverage metrics. Nine helper tests cover input
integrity, missing inputs, paths, candidate overlays, committed identities
and authenticated archives. Two original inputs remain in
`frozen-prior-inputs/` after reviewed corrections to their live packets;
the frozen manifest and its hashes are unchanged. Additional candidate
records can add conflicts but cannot establish positive reference evidence.
Full before/after receipts are in `prior-repair-validation.json`.

Catalogue outputs were regenerated from their owning inputs. Raw target
records were preserved, except for the two explicitly reviewed semantic
corrections whose original snapshot bytes are retained. This work does not
supply a full node build, original compiler identity, dependency closure or
runtime acceptance.
