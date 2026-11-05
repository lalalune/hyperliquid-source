# Qualification and limits

Before new Rust, Git commit `eb1274be65964c8c7d2642505b50df40db445877`
sealed actual-instruction inputs, expected outputs, native evaluator, contract,
full exports and eleven output-changing COW controls. Freeze6 passed in63.502s;
4,293 distinct tuples. The full private150/150 instructions are visited; all
four exported bodies total319 instructions, of which309/1,128B are visited.
The excluded10/33B require a slow-reader length contradicted by this caller.
This is finite static instruction qualification, not captured execution.

Clean Rust opt0 and opt3 each match all4,293 complete raw output rows, and the
same-path opt3 rlib repeat is byte-equal with identical outputs. All128 sealed
client cases pass at both levels and on repeat. Eleven separately compiled
semantic mutants complete their full streams normally, differ in
2025/2475/562/1363/3/421/253/909/99/184/263 rows, and each fails the128-case
client fixture with ordinary test exit101. The aggregate mutant replaces the
four sequential reads with the actual unchanged dependency's read_four; it
therefore tests the substantive charge-order difference directly.

The first build run failed134.650s because a wrap mutant differed in the full
stream but escaped the initial127-case sample. The final sample adds the
unchanged sealed row4142 (count MAX-32), keeping the original expectations.
The205.690s resumed run rechecks clean streams/fixtures and all11 mutants.
Initial failed run logs and original command hashes are retained. Individual
per-command paths were reused during resume: final raw streams and the first
clean streams are archived, but not every initial command's stdout is a
separate retained payload. This limitation is explicit in the stream index.

`comparison-streams.json.gz` is deterministic gzip(mtime0) containing a JSON
object of17 complete path-free synthetic streams. The index binds each raw
stream and decompressed payload. `rust-results.json` retains exact sanitized
commands, exits, timings and raw stdout/stderr hashes. Public failure-log
projections replace only the owned work-directory prefix with `<work>`;
original local logs remain outside the repository. No mask is applied to
compared result values. Source, driver, fixture and real unchanged MIT reader
hashes bind the builds. `verify-rust.py` replays builds in a fresh owned output
directory; published build/compare functions match those actually run. CLI
compiler/output selection replaces preparation paths. Research builds use
macOS arm64 rustc1.94.1 edition2021, not the dependency's original edition2024
Cargo recipe. No Linux, original compiler, native ABI or byte-equivalence
claim is made. New code is independently authored MIT; no unlicensed inferred
source was inspected or copied.

Final scoped364.534s run:7 focused tests, rustfmt, Clippy with warnings denied,
12 packet-integrity tests, make doctor, make verify, make catalogue,
make catalogue-check and actual make reproduce all pass. `checks.json` has
exact exits and elapsed times in seconds. The new source and packet README
were staged before catalogue generation. Only catalogue generation/check
uses the already-submitted #2655 authenticated snapshot helper overlay;
`validation-overlay.json` identifies it and the measured blocker. Baseline
helper bytes are restored before actual reproduce and submission. No duplicate
helper fix or unmodified-head local catalogue result is claimed.

The base has560 tracked top-level packet READMEs despite stale generated559;
one new packet produces561. Rust areas34->35; Cargo manifests stay19.
Only the serialization implementation path is registered. All92 gates and
byte registrations remain unchanged. The first ten submitted sibling heads
have observed full584/585-file zero-failure upstream CI; that shared evidence
is not a fresh full-suite result for this head. A full local make test is not
claimed; this PR's upstream full CI must be observed separately. No merged
integration tree, node runtime or whole-component completion is asserted.

The original block-fill packet, dependency source, original reader packet,
shared tools, captured artifacts, import pins and old tests are preserved.
All local heavy jobs run serially under the approved duty0.10 process-group
limiter. This is an active-wall duty ratio, not a guaranteed aggregate CPU
percentage. No other processes, live services, signing or chain are touched.
