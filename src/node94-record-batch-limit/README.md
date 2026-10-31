# One node #94 scalar batch-limit family

This independently authored, safe `no_std` Rust module implements the complete
numeric family already proved in [the original #1043 packet](../../research/work-items/RE-001-gap56319fd-variable-records/PROOF.md).
For arbitrary ten unsigned 64-bit input words it computes:

```text
d = input0 - lower                 modulo 2^64
r[i] = ends[i] - outputs[i]        modulo 2^64, each of four lanes
q = min(d / 7, r[0] / 10, r[1] / 10, r[2] / 10, r[3] / 10)
stop = outputs[3] + 5*q            modulo 2^64
zero_guard = (stop == outputs[3])
```

Division is unsigned floor division. Each lane participates independently.
`q <= u64::MAX / 10` proves multiplication by five cannot overflow; the final
addition can wrap. Nevertheless `zero_guard` is true exactly when `q == 0`,
equivalently when `d < 7` or at least one modular remainder is below ten.
For example, `q=1` and `outputs[3]=u64::MAX-4` give `stop=0` and a false guard.

The API and result struct are newly chosen Rust, not original types or ABI.
The words are **raw scalars**, not validated pointers or capacities. Input and
output subtraction underflow remains defined modular arithmetic. A false
zero guard supplies none of the original subsequent input-order checks,
table contents, nonzero BSF operands, live regions, write/refill behavior,
progress or termination. This module does not implement the record loop.

## Build and compare

Use the existing trusted compiler matching the repository's research pin,
`rustc 1.94.1`; it is not a recovered original node compiler. The module has
no dependencies, Cargo workspace, build script or unsafe code. Ordinary
direct builds and tests are:

```sh
rustc --edition=2021 --crate-name node94_record_batch_limit --crate-type=rlib \
  -D warnings -C overflow-checks=on -C opt-level=3 \
  src/node94-record-batch-limit/lib.rs -o /tmp/librecord_batch_limit.rlib
rustc --edition=2021 --test -D warnings -C overflow-checks=on \
  src/node94-record-batch-limit/lib.rs -o /tmp/record-batch-tests
/tmp/record-batch-tests --nocapture
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/node94_record_batch_rust.py \
  --rustc /path/to/trusted/1.94.1/rustc --output /tmp/batch-new --controls
```

Choose new output paths. The runner authenticates the actual node #94 input
and regenerates the checked-in fixture from the retained unsigned
multiply-high/shift/add/sub/min expression. It does not obtain expected
answers from Rust division or production output. An external comparison
harness links the production `.rlib` and reads **input words only**; Python
compares its actual output with the separate target-derived stream. This is
reviewed data flow, not OS filesystem sandbox isolation. The ordinary Rust
test separately reads the fixture and checks the production function.

The runner performs unoptimized and optimized builds, compiling semantic
mutants and two raw own-library rebuilds. No captured node, concrete CPU
interpreter or emulator is run. All sixteen original #1043 files remain
unchanged. The [sibling Rust evidence packet](../../research/work-items/RE-001-gap56319fd-batch-rust-94/README.md)
records commands, actual counts, negative controls and remaining limits.
There is no original binary comparison, full helper or progress-gate claim.
