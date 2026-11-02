# Existing-provider qualification phase

The root pre-code gate authorized authoring this input-only client and harness,
not compilation. No production file is changed. All 31 original packet files
remain immutable, as do the existing 11-file MIT `node94-action-signable` crate
and its repository license. `SOURCE-PROOF.md` gives the complete source value
argument against the frozen native/mathematical contract. This phase does not
add a Visor wrapper or claim a newly recovered Rust implementation.

The actual crate has one dependency-free library target; its 14 existing unit
tests are inline. `src/tests.rs` also includes the existing repository-relative
`research/work-items/RE-005-action-signable-94/vectors.tsv`. The exact 124,890-byte
fixture, SHA256 `4fc3c82f6e362766a4831c0f3b973bb7b2bff4786319ab68df66397f393ba9b8`,
has 1,008 data rows. The isolation preserves the real `src/` and `research/`
relative layout so the unchanged tests can compile. This test-only data input
is separately pinned in the additive source phase; the old pre-code freeze is
not rewritten. Its historical evaluated vectors are not new Visor expectations,
and their original evaluator/generator is never run by this harness.

The new client receives only opaque IDs and decoded message bytes through stdin
and calls the real exported `keccak256`. It never receives oracle/expected files,
semantic labels, target bytes or file paths. Its code buffers output until all
input has parsed successfully. The independent 2,000-case expectations and all
official vector checks remain the exact pre-code bytes.

## Actual preparation, before compilation

`LOCK-ADMISSION.json` records six actual commands: Cargo/rustc/rustfmt version
queries, formatting the new client, checking the unchanged existing Rust files
and client, and full offline/locked Cargo metadata in a fresh isolated copy.
The existing lockfile is used unchanged; it is not generated or invented here.
Metadata reports exactly the real library package with no dependencies and its
copied component as workspace root. The existing provider files and external
fixture remain byte-identical. No Cargo build/test, rustc compilation, candidate
execution, target or evaluator occurred in preparation.

All 97 installed toolchain `bin`/`lib` payloads and symlinks are pinned. Current
lexical/canonical ancestor Cargo configuration and workspace manifests were
checked for the original source and the temporary preparation root. A fresh
Cargo home, explicit direct compiler paths and offline/locked commands are used.
`HOME` is preserved and never repurposed. Exact private raw command output is
retained; public structured paths use declared logical prefixes. Normalized
metadata is not represented as raw-byte-identical to the private metadata stream.

## Planned gated execution

Only after a gate naming the exact later `SOURCE-FREEZE.json`, run from this
packet's directory using the canonical harness path:

```sh
python3 -B rust-validation/build.py \
  --toolchain /absolute/path/to/1.94.1-aarch64-apple-darwin \
  --out /tmp/a-fresh-visor-keccak-build \
  --private-map /absolute/private/path/visor-keccak-build-map.json \
  --source-freeze-sha EXACT_SOURCE_FREEZE_SHA256
```

The output must be a fresh direct child of canonical `/tmp`; its lexical and
canonical ancestors are both audited, including `/private/tmp` on macOS. The
private map must be fresh and outside the public packet. The harness rejects
unadmitted source/harness symlinks, Cargo configs/workspaces, source/fixture
changes and graph/toolchain differences before compiling. Actual metadata is
rechecked for every baseline/repeat root. Selected linker/SDK identities are
observed and rehashed around the build; OS/dyld/full SDK hermeticity is unclaimed.

For post-source static replay, the harness first copies exactly the 31 frozen
pre-code files into a directory with no `rust-validation` child. It runs that
unchanged verifier with the actual authenticated baseline repository passed via
`--repo`, preserving the original new-client-absence guard. The exact normal
pre-code receipt must match. This provides a usable post-source path without
editing or pretending to rerun the original verifier in its now-extended folder.

The planned compiler qualification has three separately identified observations
in both debug/release: first baseline, a clean rebuild at the same absolute
path after removing only that private target/client output, and a second fresh
directory with the same relative layout. Before any repeat deletion, exact first
rlib/client bytes are compressed into private content-addressed archives, then
rehashed and decompressed against the live bytes again. Every later compiled
artifact is also retained before its value run. All raw comparisons use bytes
without normalization or masks; debug inequalities are recorded without an
unestablished cause. Public artifact identities do not imply public distribution
of binaries that may contain private paths.

The 22 exact source-copy mutants affect only `src/keccak.rs`, covering domain,
rate, padding, full/remainder absorption, input/output endian order, output lane,
round count/constant, theta, rho/pi, Chi and Iota. The original provider remains
unchanged. Each mutant must compile in both profiles and emit all 2,000 valid,
ordered output frames with a value difference. Syntax/lint failures, panics,
timeouts, missing or malformed streams are failures, not semantic kills. The
baseline's 14 existing tests are run in both profiles; they remain separate
from the new independently frozen value comparison.

Ten comparator corruptions, 18 malformed input streams, one extra-argument
refusal and one empty valid input check the evidence boundary. If all checks
finish, the plan is 190 child commands, 19 expected exit-2 refusals, and 50
complete 2,000-frame value streams (six baseline/rebuild and 44 mutant).
These are planned totals only; observed receipts must report any smaller failed
run exactly. There are 25 source-copy observations across 24 physical roots,
because the same-path repeat reuses one source location after retaining its
first compiled bytes.

## Retention limits

Every child stdout/stderr byte returned to Python is retained in deterministic
content-addressed gzip before exit-status or private-path rejection. Timeouts
retain the partial streams attached to the exception and no invented exit code.
Launch failures have empty child streams, a separate retained diagnostic, and
no child exit status. No promise is made about bytes Python never receives,
descendant processes or abrupt termination of the harness itself. Exact compiled
bytes stay private; public output uses identities and explicitly mapped paths.
Runtime caches must be excluded from any later publication manifest.

The source proof and admission are not evidence of compilation. Actual baseline,
test, repeat, mutant and raw-output outcomes remain pending a separate gate and
real execution. No original target compiler/ABI, live filesystem, cryptographic
security or full-module completion is claimed by a successful future host run.
