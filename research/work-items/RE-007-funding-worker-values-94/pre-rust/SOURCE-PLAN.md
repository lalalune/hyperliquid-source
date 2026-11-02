# Source and dependency plan before Rust

After root's proof/corpus gate only, add exactly one dependency-free component
under `src/node94-funding-worker-values`: Cargo.toml, a real generated Cargo.lock,
README.md, src/lib.rs, and focused integration tests. No workspace, registry
dependency, build script, proc macro, native FFI, network, unlicensed source,
captured byte execution or copied target instructions. BTreeMap/BTreeSet/Vec
are standard-library storage for supplied values, not a claimed native Btree.

The library will implement the qualified value operations from CONTRACT with
explicit domain refusals. Narrow binary64 conversion and multiplication will
use integer significands in u128, bit-length/exponent arithmetic, discarded-bit
comparison and tie parity. This avoids relying on the host's floating control
state, and is different from oracle.py's Fraction plus binary search over
neighboring representable reals. The correspondence to native SSE remains
conditional on the documented MXCSR and helper-frame premises. No generic
floating-point library or arbitrary opcode interpreter is planned.

Finite binary64 significands have at most53 bits; multiplying the rounded
integer significand with rate significand needs at most106 bits and fits u128.
The integer input magnitude needs at most64 bits, including i64::MIN. A
software rounding helper can select quantum=max(top_exponent-52,-1074), round
the discarded remainder to nearest/even and normalize a possible carry.
Shifts whose counts exceed the integer width must be handled explicitly,
without Rust shift overflow or fictitious wrapped masks. Normal, subnormal,
zero, overflow-to-infinity and sign classification all belong in the proof.
NaN/Inf inputs need only their resulting nonfinite class for amount0; raw rate
payload is preserved independently. No NaN arithmetic payload is an API result.

The real source/lock, tests, input-only driver and packet-local build harness
will be audited and frozen before any compilation. The driver reads only opaque
case IDs and supplied input frames, outputs actual value frames, and cannot read
expected fixtures. It uses the real crate manifest/lock. The harness uses pinned
installed Rust binaries, fresh canonical build paths, offline/locked builds,
an allowlisted environment, ancestor Cargo-config audit and retained raw streams.
Debug/release tests and all frozen cases must match; actual compiled source
mutants must differ. Source-copy admission must bracket each run. Same-source
clean rebuilds must retain raw artifact identities and report any path-dependent
differences honestly. No repeated build is authorized solely to force equality.

The immutable pre-source corpus is not native execution or differential testing.
Any later missing discriminator will be an explicit supplement, never relabeled
as frozen before source. No production file or driver is created before the
coordinator independently reviews this contract, native proof and corpus.
