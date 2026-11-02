# Coordinator validation

The coordinator inspected authenticated GNU disassembly and the complete new
Rust library, checked frozen/source/qualifier hashes, compared every row of
all four retained primary outputs, and replayed a hash-bound compiled sample.
This is internal validation, not a submitted GitHub review.

Shared native base `e5c9b6436876b2a4a39daef813171f9879317699` with independent
additive packets: `make doctor verify catalogue-check` and `make reproduce`
passed. `timeout --signal=TERM --kill-after=10s 90s make test` exited124:
9/971 files started, 8 completed with247 reported tests, no failed summary.
The ninth was interrupted. This is not a whole-suite or per-head full pass.
Exact records and sanitized raw logs are in `checks/`. No captured binary,
emulator, desktop/browser, chain or live-service operation was used.
