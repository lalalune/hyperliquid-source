# Current implementation and qualification

The dependency-free crate [`src/node94-funding-worker-values`](../../../src/node94-funding-worker-values)
implements one supplied user's qualified funding-worker values. The public
function takes explicit immutable inputs and state, then returns eligibility or
ordered state updates, active rows, saturation-request records and the first
maximum absolute **checked product** summary. Its binary64 relation uses integer
significands and exact nearest-even rounding; it does not depend on host floating
controls. Original rate bits, including NaN payloads, remain active row values.

This is the current implementation-phase entry point. [README.md](README.md)
remains the unchanged earlier static/pre-source snapshot. Read the full native
[PROOF.md](PROOF.md), frozen [value contract](pre-rust/CONTRACT.md), and later
[source proof](SOURCE-PROOF.md) for the correspondence and its limits.

Author qualification passed the real crate's eight integration tests in debug
and release, Clippy, and all **10,945 original pre-source cases plus two separately
frozen post-source cases**, in both profiles and two clean build directories.
All 16 actual compiled mutants emitted complete successful streams and differed
from the combined expectations. Eight comparator corruptions and six malformed
client inputs were rejected; empty input produced an empty stream. Full raw
outputs and the exact commands are retained in
[`rust-validation/author`](rust-validation/author).

The first qualification did not pass: the `size-before-index` mutant survived
the original corpus, which omitted size zero combined with out-of-bounds
metadata. The source-frozen handwritten test already covered that native guard
order. The coordinator reviewed two independently specified cases, then approved
a separately frozen continuation. The original corpus, source, driver, harness
and all chronological freezes are unchanged. [FIRST-RUN.json](FIRST-RUN.json)
retains the 81-command failed run (15 executed mutants, 14 distinguished), and
the [supplement contract](post-source-supplement/CONTRACT.md) explains the two new
cases. These are explicitly post-source expectations, not retroactive additions
to the original pre-source corpus. No production value correction was needed.

Both library rlibs and release clients matched their clean-directory rebuilds
byte for byte. Debug clients differed. No bytes were masked or normalized, and
no additional build was run to force equality. These observations qualify the
pinned host build, not the captured Linux binary or all possible toolchains.
See [VALIDATION.md](VALIDATION.md) for reproduction and exact phase identities.

The native correspondence remains conditional on valid finite stable trees,
pointer/count/alias and frame premises, exact successful allocation/copy effects,
normal opaque-helper returns, and the specified SSE environment. Rust standard
collection storage must succeed. Safe API refusals do not reproduce native
failure state or rollback. Request records do not deliver native diagnostics.
No economic units, native Btree layout, scheduler coverage, whole settlement,
captured execution, instruction interpreter, public risk gate or original
compiler/ABI equivalence is claimed.

The earlier distribute-funding and rate formula work remains credited in the
static snapshot. The seven retained native ranges total 5,785 bytes/1,291 rows;
the three primary ranges total 3,202 bytes/708 rows. Supporting/context bytes
are not extra completion credit. Source and packet are the only new owned paths;
repository-wide integration, hosted CI and publication remain separate steps.
