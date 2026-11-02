# Validation and chronological evidence

All qualifications here concern the independently authored supplied-state Rust
component and static native evidence. No captured executable or captured
instruction evaluator ran. The installed host toolchain is Rust/Cargo 1.94.1
`aarch64-apple-darwin`; 97 actual `bin`/`lib` payload files are pinned before and
after builds. Linker binaries and selected SDK inputs are also pinned. The host
OS/dyld and complete SDK are outside the hermetic boundary.

| Phase | Preserved identity / evidence |
| --- | --- |
| Static proof | `STATIC-FREEZE.json` SHA `436921db3acf51a34093d5547400c3de093ae55c9952ed2cb9ac88c9f163d513`; 989 rejecting controls, two matching native regenerations |
| Independent pre-source corpus | `pre-rust/PRE-RUST-FREEZE.json` SHA `e6555491429b7327c5b78c6f71d57f005c629bd5464ca9ed4b03fa5cfdc733b6`; 10,945 cases, 13 mathematical controls |
| Source and original harness | `SOURCE-FREEZE.json` SHA `89d7df78abf6bd9c54efa6685a9a1c1b9d65c829e5fd32e2747d8256e1bf5464`; real dependency-free lock, five crate files, input-only driver and harness frozen before first compilation |
| Initial failed qualification | `FIRST-RUN.json`, `rust-validation/first-run/`; all four production/rebuild streams matched; 14 of 15 executed mutants differed, `size-before-index` survived; sixteenth not yet executed |
| Post-source supplement | `post-source-supplement/SUPPLEMENT-FREEZE.json` SHA `7dbda00f104d054e00e27f74a6422266892be3f515bf1760c9bfac74e565d200`; two independently specified guard-order cases and new continuation harness |
| Successful continuation | `AUTHOR-QUALIFICATION.json`, `rust-validation/author/results.json`; 84 commands, four matching 10,947-case streams, all 16 compiled mutants distinguished |

The root pre-source gate and author source freeze both preceded compilation.
The coordinator's final source/harness review completed after the author had
started the first build. The author suspended that harness with SIGSTOP when
the review hold arrived and resumed it with SIGCONT only after explicit release.
This is not described as a coordinator source review before first compilation.
`FIRST-RUN.json` records that sequence; command elapsed times were retained
unchanged. Exact signal timestamps were not independently recorded.

The original corpus's raw expected stream SHA is
`234f90c71df3eda148c9465c71af9e0ca5455bb96790c0d42efe16b5972bc2c3`.
The post-source supplement's expected stream SHA is
`a5e1eff16594bb6deb96f3398774d50f25687be3dd493b3f6f5ac2c5e64d8641`.
The continuation reports original, supplemental and combined comparisons
separately, including the fact that the guard-order mutant differs only on the
new out-of-bounds/zero-size case. The other 15 mutations are distinguished by
the original cases.

The actual crate's eight integration tests pass in both profiles, with Clippy
warnings denied. The separately linked client receives only input frames on
stdin, no arguments, categories or expectations. Six malformed inputs exit two;
empty input succeeds with no output. Eight independent output corruptions are
rejected. A mutant counts only after successful compilation, successful client
exit, all expected frames and actual output disagreement. No compilation failure
or missing output is credited as a value disagreement.

Both profile rlibs reproduce exactly across the two author clean directories;
release clients also reproduce exactly. Debug clients do not. The result files
retain their actual hashes, unmasked comparisons and canonical path-presence
observations. No cross-platform, universal or captured-target byte equivalence
follows from these observations.

Every subprocess stdout/stderr stream is retained as lossless content-addressed
gzip: 162 stream references in the failed run and 168 in the successful run.
The continuation has 60 unique raw stream files; the failed run has 57. Gzip
preserves raw bytes, and all raw length/SHA records were independently rechecked
when copying the author receipts. Repeated references share their hash file.
Private physical build mappings remain outside the packet; command metadata
uses logical paths, while raw command output is unmodified. Small gzip evidence
is exempt from Git LFS through the packet's `.gitattributes`.

To repeat the successful continuation from the repository root, provide an
installed toolchain with the pinned payload, a nonexistent direct child of
canonical `/tmp`, and a nonexistent private-map path outside this packet:

```sh
python3 -O research/work-items/RE-007-funding-worker-values-94/build-supplement.py \
  --toolchain /path/to/rust-1.94.1-aarch64-apple-darwin \
  --out /tmp/funding-worker-fresh \
  --private-map /tmp/funding-worker-private-map.json \
  --source-freeze-sha 89d7df78abf6bd9c54efa6685a9a1c1b9d65c829e5fd32e2747d8256e1bf5464 \
  --supplement-freeze-sha 7dbda00f104d054e00e27f74a6422266892be3f515bf1760c9bfac74e565d200
```

The harness rejects changed frozen files, source/harness symlinks, extra source
files, dependency/hook changes and lexical/canonical ancestor Cargo configs.
It uses a fresh `CARGO_HOME`, an allowlisted environment and offline locked Cargo
commands. Source-tree ancestor workspace/config presence is recorded as context
excluded from the isolated build; user configuration contents are not read.
Copied sources, the input driver, toolchain payloads and selected external inputs
are checked again after qualification. The original `build.py` remains available
to reproduce the initial surviving-mutant outcome with its original freeze;
that intentional historical failure is not a current passing qualification.

For the native collector and exact-Fraction corpus regeneration, use the earlier
README commands. The static hashes and tests bind the manual proof to selected
bytes; finite source tests and corpus matches supplement that proof rather than
establish universal semantics on their own. No full-repository suite or hosted
CI result is claimed by these receipts.
