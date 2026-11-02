# RE-005: integral padding request and header effects

This packet closes the normal callback/header/low-AL relation behind the unsigned
numeric selector's opaque integral-padding edge. It covers node #94's complete
1,295-byte main function and its real 84-byte prefix and 1,483-byte character
counter helpers. The source is independently authored safe Rust; no original
binary code is linked, emulated or copied into an implementation. Rendering,
private ABI, faults/unwind and full component identity remain outside the claim.

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Current source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
The component contract, complete native denominators and safe domain are in
`src/node94-integral-padding/README.md`. `SEMANTIC-PROOF.md` states the native
branches, method/data caching, prefix counting and return/header relation.

## Chronology and independence

The `independent-pre-source/` corpus and authority were sealed on 2026-11-01
before the preserved uncompiled Rust was authored. `FREEZE.json` SHA-256 is
`f280241cfed45a374378e9af99f2247f44d22ed3143550a9421efe5d71a54f6a`.
It binds 11,150 distinct complete inputs, 1,086,315 individual callback
observations and 30,343 exact RLE records. The full authority is retained as
lossless zlib with its original identity in `AUTHORITY-COMPRESSION.json`;
inputs and exact expected JSONL are uncompressed. The independent proof and
handoff retain their original pre-source chronology.

This work paused before any new padding compiler run when the user switched
repositories. The old `3324e503` worktree and original untracked files remain
intact. `PORT.json` records a byte-identical port of those owned files into a
fresh current-base worktree. Added documentation and execution guards do not
restamp the historical proof. `independent-review/` includes fresh native/math
readmission, source/runner review and the current-base identity delta.

There is no suitable competing open PR found by the retained live ownership
intake. The accepted numeric-selector, PadAdapter byte/character and published
libcore correspondence packets are supporting distinct work. No gate or new
captured-byte match is requested here.

## Reproduce the scoped experiment

Use the admitted official Rust research provider and its actual installed
libcore archive. Its 103-payload manifest is SHA-256
`56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6`;
the libcore archive itself is
`ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`.
The provider path is configurable only through that authenticated manifest.
The native object's copyright/license identity is supporting provenance, not
proof that the target used this original compiler.

From a clean source/evidence commit descended from the stated current base,
choose a fresh output directory outside the checkout and run:

```sh
python3 -B research/work-items/RE-005-integral-padding-94/validate_padding.py \
  --root "$PWD" --output /tmp/padding-new-run \
  --head "$(git rev-parse HEAD)" \
  --provider-audit /path/to/PROVIDER-AUDIT.json \
  --core-archive /path/to/libcore-e60dd2ab51fbc7de.rlib
```

The runner performs bounded static parsing/disassembly and executes only newly
compiled authored Rust. It records actual compiler/linker versions, exact
commands and raw stdout/stderr, full tracked physical input hashes and modes,
seven genuine pinned repositories, all 103 provider payloads and target/archive
identities before/after. Positive input-only client output must match the exact
sealed canonical JSONL bytes. O0/O3 unit/client checks, one same-recipe optimized
rebuild, eleven compiled source mutations, seven below-digest native controls
and seven comparator controls are scoped checks, not a node evaluator.

## Observed results

The first actual padding build passes at clean source checkpoint
`255eea2cc3ae6f75b807b4f000af455c710f4b6f` (tree
`3bb7cac1bc118085688b0a9c99646e7d9ca192ab`). O0 and O3 input-only
clients each emit all 11,150 exact sealed JSONL rows, covering 1,086,315
individual callback observations per profile. Both profiles pass the two actual
Rust unit tests. An additional same-recipe O3 rlib and input client are raw-equal
to the first O3 artifacts; this is not a captured-machine-code comparison.

The eleven independently recompiled source controls produce respectively
14, 1,112, 464, 1,208, 199, 388, 2, 764, 21, 21 and 1,023 differing complete
rows out of 11,150 (runner order). Seven below-whole-digest native controls and
seven comparator controls pass, including noncanonical whitespace, duplicate
JSON keys and Boolean/integer confusion. Positive output requires exact bytes.

`build/RESULT.json` and `build/CALLS.json` retain 50 recorded compiler/program/
identity commands with 100 exact streams. Internal bounded native binutils
commands are recorded separately in the native exports and report. The raw
stream pack preserves each distinct original content once, including full
before/after input audits and exact mutant sources. It excludes runnable own
executables/libraries and full captured ELFs. The small captured/official native
body excerpts are explicitly included as static evidence with `NOTICE` and the
full upstream `LICENSE-MIT`.

`repository-checks/` retains actual `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` results at the same clean source
checkpoint. All four pass, with all 10,834 tracked physical inputs, seven genuine
pins, 103 provider payloads, target/archive/linker identities and HEAD/tree/status
unchanged. `independent-review/` retains the full artifact review and a public-safe
summary of 28 additional holdouts, sealed after source review but before build.
Both retained clients pass those supplemental inputs, including 65,537 callbacks
in one case. This is later corroboration, not a second pre-source independence
claim. Private holdout inputs/answers and runtime state are not published.

Full `make test`, expanded instruction-evaluator families, hosted CI, captured
node/visor execution and a full node build are **NOT_RUN**. The draft uses
`[skip ci]` to preserve that scope. Existing component gates stay false.
