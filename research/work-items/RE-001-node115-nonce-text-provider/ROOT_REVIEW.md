# Coordinator and independent peer review

The coordinator read the proof and complete collector/verifier, independently
reviewed the complete integer, growth, reserve, allocation and closing bodies,
and checked the early provider/error paths. A separate agent read every
selected native instruction and the full caller. Three findings were corrected
before submission and then reread by that reviewer:

- The opaque error factory can return RAX unchanged through the closer. The
  grammar/completion claim now explicitly assumes a nonzero valid error object;
  a zero return after an invalid delimiter is an excluded counterexample.
  First-field decoder preservation of live mode/depth/outer storage is explicit.
- Early provider EOF/depth1 paths bypass the selected decoration function.
  Result tables now call these error payloads without inferring decoration.
- Initial closer exhaustion selects class2; post-comma exhaustion selects0x16.

No native data, spec, collector logic or verifier changed for these corrections.
Final staged whitespace checking removed one extra LF at collector EOF; its
exact reversible hashes and AST-equality check are recorded in VALIDATION.json.
The reviewer found no remaining actionable defect. Original and corrected
source hashes are retained in VALIDATION.json, with the review receipt below.

The coordinator actually reran verify.py:168 controls and two fresh exports
passed, with JSON equal to retained verification.json. Independently written
raw-file review used PT_LOAD mappings and parsed all12 FDE/CIE records and
unwind-index links, both native export partitions (4,917 bytes/1,273 rows),75
anchors,17 required RELATIVE records, all20 call-slot bindings and23 LSDA
call-site rows. This avoids relying solely on the collector's section/parser
helpers for those bindings. It does not execute instructions or prove the
manual semantics mechanically. `make -j1 verify catalogue-check` passed.

Fresh open-PR body/path review through#1394 found no declared overlap with
this provider/caller scope. The prior ordering theorem remains credited to
#1003. Research provenance predates the current56c0ec67 base; pinned target
and dependency hashes were checked on the current base. Undeclared work cannot
be excluded. No progress gate advances.

All native conclusions retain the explicit memory/callee/allocator premises.
Actual freeing, floating values, opaque first-field semantics, public nonce
policy, exceptions and whole-program reachability are unproved. No captured
executable, instruction evaluator or unrestricted test suite ran.

Coordinator-local receipt hashes (no authentication material):

- `root-nonce-provider-verify.json`: `fa3f49722c430e902360a5cbc8b0cc2b563066e865f882044d9ea5163df42b58`.
- `nonce-provider-root-native-review.json`: `c60e533481cbbae475358a7f792bd9497ccf6a5a979967cf7dfeadaf3112d112`.
- `nonce-provider-independent-peer-review.json`: `74a0f90a75b079f26d84742dc60276dfd209239b920eb9f23f9bfbfc6d532456`.
- `nonce-integration-static-checks.log`: `4d6919f9e2d8ab98f1a1233b01aa40d0e415b3b6978338c374dbbbf1b2ee699e`.
