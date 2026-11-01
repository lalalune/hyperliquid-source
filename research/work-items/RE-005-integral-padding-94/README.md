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

At source checkpoint, the padding compiler experiment has **not run**. Actual
results will be added only after the commands complete and independent artifact
review. Required static repository checks are `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce`; their exact-head results will be
retained separately. Full `make test`, expanded instruction-evaluator families,
hosted CI, captured node/visor execution and a full node build are **NOT_RUN**.
The draft uses `[skip ci]` to preserve that scope. Existing component gates stay
false.
