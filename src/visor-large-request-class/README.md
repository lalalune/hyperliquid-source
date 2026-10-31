# Visor large-request numeric class

This independently authored, dependency-free `no_std` library computes one
numeric class from an unsigned raw request. For `4097..=0x7000000000000000`,
`large_request_class` returns `Some(class)` in `29..=231`. For every other
`u64`, it returns `None` to mark **only this newly chosen API's restricted
numeric domain**. `None` does not claim that the original allocator fails,
returns null, writes errno, or rejects a small request.

The native proof binds the captured visor SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
Its selected large-request expression uses `BSR(2*r-1)`. On the domain,
`0 < 2*r-1 <= 0xdfffffffffffffff`, the BSR value equals
`bit_length(r-1)` in `13..=63`, and both observed clamps are inactive.
The Rust implementation independently computes that value with `leading_zeros`
on `r-1`, then computes the two-bit fractional class and bias. Shifts are
`10..=60`; its `u32` arithmetic fits without wrapping. The native proof's 203
contiguous integer intervals cover every integer in the domain. See the
[target-bound derivation](../../research/work-items/RE-013-visor-allocator-large-request/PROOF.md).

The interface is newly chosen Rust, not an original private ABI, type or unit.
Use of this class by the selected native entry additionally requires its raw
FS-relative byte-zero route. This pure helper does not read TLS, initialize a
cache or class table, allocate, copy, or implement the native error-call/store/
canary/return path. Allocation success, freshness, alignment, capacity, lifetime,
original compiler/byte identity and component gates remain unqualified.

## Actual build scope

The module belongs to the repository's `src/` implementation area. It is built
directly with the existing verified **research rustc 1.94.1**, without a Cargo
workspace, dependencies, lockfile or build script. This pin is not a recovered
original visor compiler. The reproducible runner checks the measured compiler
executable identity and records full `-vV`, explicit C linker driver identity,
flags and all raw subprocess outputs.

```sh
/path/to/verified/rustc --edition=2021 --crate-name visor_large_request_class \
  --crate-type=rlib -D warnings -C overflow-checks=on -C opt-level=3 \
  src/visor-large-request-class/lib.rs -o /tmp/libvisor_class.rlib
/path/to/verified/rustc --edition=2021 --test -D warnings \
  -C overflow-checks=on src/visor-large-request-class/lib.rs \
  -o /tmp/visor-class-tests
/tmp/visor-class-tests --nocapture
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/visor_large_request_rust.py \
  --rustc /path/to/verified/1.94.1/rustc \
  --output /tmp/visor-class-build-new --controls
```

Use fresh physical output directories. The runner first authenticates the
actual visor through one read-only view, derives the native raw-operand proof,
and compares both retained interval and unit-vector TSVs with fresh expected
values. Its expected values come from membership in the native proof's 203
integer intervals, not Rust output or a Python copy of `leading_zeros`.

The actual production library is separately linked into a harness that reads
**input values only**, not expected answers. The parent runner compares stdout
with the separate expected stream. This is reviewed data-flow separation;
expected files are not hidden by a filesystem sandbox. The ordinary Rust test
uses `target-vectors.tsv`; `cfg(test)` and that fixture are excluded from the
production library. The corpus distinguishes target-proved `Some` values from
chosen out-of-domain `None` values.

Unoptimized and optimized real builds, input-only production comparisons,
compiled semantic mutants and raw own-library rebuild comparisons support this
bounded implementation. They do not execute or emulate the captured visor,
prove compiler correctness, or compare new machine code with original bytes.
Full observed counts and limits belong to the [Rust evidence packet](../../research/work-items/RE-013-visor-large-request-class-rust/README.md).
