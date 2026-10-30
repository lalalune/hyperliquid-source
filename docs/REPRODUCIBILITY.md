# Reproducing the research

`make verify` checks every manifest artifact's SHA-256 and size, then verifies
all three detached signatures against the pinned public-key fingerprint in an
isolated temporary GPG home. It checks the #94 binary/signature against the
pinned can1357 reference and the public key against the pinned official repo.
It also checks imported research hashes and source commit pins.

`make reproduce` writes #94/#115 inventories and a fresh literal classification
to work/reproduced/. `tools/legacy/drift.py` is preserved as imported: its distinct
unit is **(top-level crate, literal)**, not a globally unique literal, and its
lexical matching is heuristic rather than a Rust parser. It excludes strings
shorter than 8 characters, strings containing `{`, and selected single-line
compile-time attributes. It can include comments and test literals. Partial
matches include three-word windows, short whole phrases and case-only matches.
It does not prove semantic equivalence or validate tests.

The raw output is checked against the imported aggregate counts. The 46 imported
item-level refinements in provenance/literal-overrides.json are then applied
with exact class preconditions. Aggregate and per-crate totals are recomputed,
and final items are compared by literal, crate and class, ignoring first-file
attribution order. A mismatch fails the reproduction command. Inventories are
compared as parsed JSON. Both raw and refined outputs are retained under work/.

Never edit imported results to agree with a narrative. See research/STATUS.md
for the stale aggregate fields in the saved JSON; its item-level labels
match the supplied written summary.

`make fetch` downloads only absent files and verifies bytes before an atomic
rename. It tries every manifest file, then fails once, listing each file it
could not recover. An existing damaged file fails rather than being
overwritten; a Git LFS pointer in place of a binary is reported as such and
also left alone (`git lfs pull` replaces it; without Git LFS, deleting it lets
`make fetch` download a file that has a recovery URL, but Git then shows the
binary as modified, so do not commit it). #94 has
a commit-pinned GitHub LFS recovery URL; the visor publisher URL is
mutable and may fail the historical checksum. #115 has no verified immutable
public recovery URL; retrieve it via project Git LFS. Metadata is retained in Git. Git LFS is the canonical complete retrieval path.

Host validation on 2026-10-28 used macOS/arm64, Python 3, GnuPG,
Git LFS 3.7.1 and LLVM 22.1.4. Docker was unavailable, so the container
definition has not been build-tested. These host versions are not target
build provenance.
