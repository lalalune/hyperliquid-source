# RE-001: Rust for fourteen node94 raw cumulative-minute conversion windows

Component: foundation time conversion, selected scalar/guard relation only.
Target node94 SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280bytes. Basee5c9b6436876b2a4a39daef813171f9879317699; freezefe972230.
Credit merged#140 and unchanged RE-001-cumulative-minute-94. OpenPR1355 studies
two input-producer/caller compositions; those claims/files are excluded here.
The existing byte-backed theorem supplies no Rust conversion implementation.
New code is independently authored MIT, with no inferred reference copied.

## Contract and evidence boundary

The old packet retains eight actual full FDE exports(36214bytes), raw body
hashes and fourteen inlined instruction windows tied to base/src/cumin.rs:21:13.
We regenerate the complete retained records, division certificates, source/data
and relocation bindings unchanged. These are credited dependencies, not new
full-function coverage. window-bindings.json pins all selected raw bytes and
independently decoded input memory roles/output registers/branch destinations.

Each window zero-extends one raw u32 load. Its multiply/shift expression
reduces to floor(raw/60): the original reciprocal certificates cover every
u32 value and prove the intermediate-width bounds. Guard order is unsigned
result>65535 **before** result>=1441. Accordingly:

| Raw word | Local relation |
| --- | --- |
|0..86459|Accepted(floor(raw/60)), including1440|
|86460..3932159|assertion edge|
|3932160..u32::MAX|earlier narrowing-failure edge|

The Rust enum labels those selected local routes; it is not an original
Result/error ABI or a timestamp constructor. In particular the raw interval
86400..86459 passing locally does not establish real timestamp reachability,
a public acceptance bug or successful completion by a surrounding caller.
No assertion/narrowing helper, exception, clock or callee is implemented.

## Actual comparison and controls

Fourteen actual bounded instruction programs evaluate4594distinct raw words:
minute boundaries0..1441 with offsets0/1/59, narrowing boundaries65534..65536,
signed/maximal raw words and256public deterministic values. All64316native
window evaluations agree; each window has the same frozen result SHA256.
These are4594logical Rust inputs, not64316distinct implementation states.
238selected instructions are visited. All calls/writes are forbidden; reads
are restricted to exactly one4-byte synthetic input. Capstone5.0.6 partitions
all fourteen windows and binds the actual base register/displacement/output
register; no register assignment is assumed identical across copies.

Freezefe972230 and14smoke rows precede production Rust. Full corpora regenerate
outside Git and are hash-checked before compiler admission. Three actual native
operand edits change the minute reciprocal, narrowing threshold and inclusive
1440 guard, and the retained static checker rejects each below the hash gate.
Original captures, pinned sources, full exports and earlier failures are kept.

Actual rustc1.94.1(e408947bfd200af42db322daf0fadfe7e26d3bd1), LLVM21.1.8, builds
no_std rlibs at opt0/opt3 with overflow checks and codegen-units1. Separately
linked input-only clients each match all4594outcomes;14compiled smoke rows
pass. Three actual compiled divisor/inclusive-bound/narrowing mutants mismatch
4266/3/3rows and fail compiled smoke(exit101). Own opt3 archives rebuild
raw-identically. Freezeexit0 in123.144wall seconds; buildexit0 in177.549wall
seconds. This is host macOSarm64 reproducibility, not x86-64 code/ELF identity.

The previous producer proves native arithmetic but cannot link compiled Rust;
this component runner supplies only that missing comparison, not general
infrastructure or an unrelated refactor. Shared modules remain unchanged.
Offline Python instruction evaluation is explicitly authorized. No native
capture, Unicorn, real IO/network, wallet/signature or chain action occurs.

## Reproduce and limits

From repository root with authenticated captures, Python3.12.14, Capstone5.0.6
and actual pinned Rust1.94.1 tools:

    python3 tools/cumulative_minute_rust.py --rustc "$RUSTC" --output /new/output
    python3 -m unittest tests.test_cumulative_minute_rust -v
    "$RUSTFMT" --check --edition 2021 src/node94-cumulative-minute/lib.rs src/node94-cumulative-minute/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node94-cumulative-minute/lib.rs --emit=metadata -o /new/lib.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node94-cumulative-minute/lib.rs --emit=metadata -o /new/test.rmeta -D warnings
    make doctor verify test catalogue-check reproduce

Output must be new. Build records preserve source/compiler/output identities
and commands, replacing private path spellings only. Native bindings, corpus
hashes, all window results, controls and smoke-copy identity precede compilation.
Five focused tests PASS88.637wall seconds; pinnedfmt and Clippy library/test
PASS; fresh catalogue-check PASS. Combined command exit0 in130.951wall
seconds, retaining nonfatal xcrun warnings in validation-results.json. Shared signed
input/import/inventory checks reuse completed#1831 only for explicitly checked
unchanged dependencies; this is not new-code or whole-suite verification.
Full make test has not completed and awaits upstreamCI; queued is not PASS.

Local jobs run serially at10%active wall-time duty with command bounds;
setpriority is unavailable and exact aggregateCPU percentage is not promised.
No new Cargo graph, dependency version, transplanted bytes, full component
gate, catalogue input or first-party byte credit is introduced. Whole callers,
valid timestamp domains, source ownership/unwind and transitive helper effects
remain unresolved. Next integrate only after the relevant time producer and
intervening memory-effect contracts have been established.
