# RE-013: an independently authored visor numeric class implementation

Task/component: RE-013 / visor. Target: the 8,305,392-byte captured visor,
SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`. This is the Rust half of
one coherent outcome with the [native proof](../RE-013-visor-allocator-large-request/README.md),
not a separate allocation implementation or a gate update. New source was
authored independently under MIT; no inferred/unlicensed reference was copied.

## Before and resulting scope

The selected request-class expression previously had no project-authored Rust
implementation or real component build. The [new no_std library](../../../src/visor-large-request-class/README.md)
now returns the proved class as `Some(u32)` on the exact unsigned raw domain
`4097..=0x7000000000000000`. It returns `None` everywhere else **only as a
newly chosen numeric API restriction**. It does not reproduce an allocator
error, a null return, TLS routing or initialization, a small-request class map,
allocation, or the native call/store/canary/return sequence.

The native proof binds five fragments totalling 251 bytes/56 instructions,
including the 88-byte numeric classifier, inside an unwind-described
7,611-byte FDE. It does not decode or close that whole FDE. Raw BSR/clamp/mask/
shift operands imply 203 contiguous integer intervals with class values
29..231. The independent Rust uses `leading_zeros(r-1)`: for the admitted domain,
`bit_length(r-1) = floor(log2(2*r-1))`, clamps are inactive and every operation
is in range. That integer proof, not a sample count, establishes the domain.
The native FS-relative byte-zero route remains an additional premise when
relating this numeric expression to the selected original entry.

## Actual build and comparison

`tools/visor_large_request_rust.py` first authenticates one read-only view of
the actual visor, obtains raw constants and intervals from the native producer,
and authenticates the same view again. It refuses changes to the retained
native interval TSV or Rust unit vectors. Fresh expected values use interval
membership, not the Rust implementation or a Python copy of `leading_zeros`.
A separately linked **production** library receives inputs only through a small
harness; it does not read expected answers. This is a source/data-flow claim,
not filesystem sandboxing: separate expectation files remain accessible.

The retained corpus has **1,876 distinct unsigned inputs**: **1,243** target-
domain `Some` class expectations and **633** chosen out-of-domain `None`
expectations. Every interval endpoint and neighbours, power-of-two neighbours,
domain extremes and deterministic full-width values are included.

Observed [RESULT.json](RESULT.json):

- Both actual unoptimized (`opt-level=0`) and optimized (`opt-level=3`) builds
  run one ordinary Rust unit test over the corpus and 1,876 comparisons through
  the separately linked production library. Every result matches.
- Five source mutants actually compile and produce **1 / 1 / 50 / 1,243 /
  1,243** differing production outputs: lower-domain inclusivity, upper-domain
  exclusivity, power-of-two k, fractional mask and bias. Each compiled ordinary
  unit test fails its semantic assertion with exit 101.
- Three bounded raw-operand counterfactuals change a class/domain witness and
  then fail target-specific partition admission. They are unpinned hypothetical
  fragments, not modified/admitted target artifacts or captured execution.
- Two independent optimized **7,102-byte** own-library builds are raw equal,
  SHA-256 `e96977c7d05a4501d4ce5f8016328b9ce15b7c409712c924f5d25d942c0c60b3`.
  No normalization is used. This compares our builds with each other,
  **not with original visor machine code**.

The 39 actual subprocess records include the compiler and C-driver identity
probes plus 37 build/test/comparison records. [RAW-LOGS.json](RAW-LOGS.json)
retains all 78 exact stdout/stderr streams with lengths and SHA-256 values;
UTF-8 re-encoding reproduces every original byte without normalization.
No executable build outputs or captured images are committed.

[BUILD-INPUT-AUDIT.json](BUILD-INPUT-AUDIT.json) records identical before/after
source/native/target identities and all 103 actual compiler-prefix payloads.
[TOOLCHAIN.json](TOOLCHAIN.json) identifies the already authenticated official
research rustc 1.94.1, full compiler commit, LLVM, host and explicit linker
driver. That compiler is **not a recovered original visor compiler**. There is
no invented Cargo workspace, dependency lockfile, build script or stub.

Reproduce the real component run with an existing verified compiler:

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/owned-short python3 -B \
  tools/visor_large_request_rust.py --rustc /path/to/verified/1.94.1/rustc \
  --output /tmp/visor-request-class-new --controls
python3 -B -m unittest discover -s tests -p test_visor_large_request_rust.py -v
```

All four Python oracle/admission controls pass normally and under `-O`, with
no skips. These checks do not substitute for the actual Rust builds above.
The initial focused run had three passes and one missing native-fixture path
setup error. Its summary and the correction to the owner's `observed/` path
are retained as [PREPARATION-FAILURE.json](PREPARATION-FAILURE.json) and
[PREPARATION-RESOLUTION.json](PREPARATION-RESOLUTION.json). Expected vector
bytes were unchanged; no failure is restamped as a pass.

## Limits

The scalar API has no original type, unit, private ABI, table-state or allocator
contract. Original small requests, nonzero entry-byte routing, opaque callees,
allocation freshness/capacity/alignment/lifetime, and complete visor behavior
remain outside it. Finite builds/comparisons support the static integer proof;
they are not a formal compiler proof, original binary equality, or a component
completion claim. Captured node/visor code is never executed or emulated.
Prior #1033 and its original and failed-run evidence are untouched. Required
exact-commit repository checks and hosted status are reported by the combined
PR's integrator separately; this packet records component observations only.
