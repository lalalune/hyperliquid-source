# One node #94 scalar expression

This independently authored, dependency-free `no_std` Rust library implements
one proven numeric relation: for every `i64`, return its Euclidean remainder
modulo the positive integer 86,400 as `u32`, in 0..86,400. It uses no allocation,
clock, file/network/chain action, unsafe code, or calls into the original node.
`i64::MIN` is supported without negating it or taking its absolute value.

The interface is newly chosen Rust, **not the original helper ABI**. The
implementation follows the target-bound whole-domain arithmetic proof in the
existing [#1033 packet](../../research/work-items/RE-009-state-dump-result-projection-94/README.md).
It does not implement that helper's status/index/callee guards, its other two
fields, calendar/clock units, private layouts or its caller. The original
helper's guarded field write is not total merely because this numeric function
is total. MIN/MAX vector cases are arithmetic cases, not observed successful
full-helper executions. No component gate or original byte identity is claimed.

## Real build scope

This is a standalone Rust library/test module under the repository's `src/`
implementation home, built directly with the documented research compiler
**rustc 1.94.1**. That pin is **not a recovered original node compiler**.
There is no invented Cargo workspace, registry dependency, lockfile or build
script. A compiler for another release is not silently accepted by the runner.

With an existing trusted actual 1.94.1 compiler (shown here as `rustc`):

```sh
rustc --edition=2021 --crate-name node94_euclidean_remainder \
  --crate-type=rlib -D warnings -C overflow-checks=on -C opt-level=3 \
  src/node94-euclidean-remainder/lib.rs -o /tmp/libnode94_remainder.rlib
rustc --edition=2021 --test -D warnings -C overflow-checks=on \
  src/node94-euclidean-remainder/lib.rs -o /tmp/node94-remainder-tests
/tmp/node94-remainder-tests --nocapture
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/state_dump_remainder_rust.py \
  --rustc /path/to/trusted/1.94.1/rustc \
  --output /tmp/remainder-build-new --controls
```

Use fresh output paths. The ordinary Rust test consumes the checked-in
`target-vectors.tsv`; the runner regenerates it from the authenticated node
before compiling and refuses edits. A separately linked production-library
harness receives **input values only**, not expected results. Python compares
its actual outputs with the native multiply-high/shift/sign/repair equations.
The expectation generator does not call Rust, `%` or `rem_euclid` to choose
expected values; the existing static algebra is distinct from the Rust
implementation. This is not captured execution or a concrete CPU interpreter.

The runner records actual debug/unoptimized (`opt-level=0`) and optimized
(`opt-level=3`) builds/tests, raw own-library reproducibility, exact argv/tool
identity, and compiling semantic source mutations. Finite comparisons support
the implementation; they are not a formal compiler proof or original binary
match. Original static source, records, native listings and receipts at
`1cf8e6b4af0a049978627dee8de0146c1303aff6` remain unchanged; current Rust
build/assumption details are in the [separate addendum](../../research/work-items/RE-009-state-dump-remainder-rust-94/README.md).
