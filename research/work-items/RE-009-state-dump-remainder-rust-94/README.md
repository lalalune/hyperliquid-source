# Rust addendum to the same #1033 numeric outcome

Component: foundation, exactly one numeric expression used by the storage
projection. Node #94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The seven original static files from commit
`1cf8e6b4af0a049978627dee8de0146c1303aff6` are preserved byte-for-byte,
including the original README, producer/tests, records/listings and manifest.
That README records the original static result; this addendum documents the
subsequent independently authored Rust implementation. It is one amendment to
the same outcome, not a second PR or new native-window recovery claim.

## Scope and proof

The new safe `no_std` helper in `src/node94-euclidean-remainder/lib.rs`
returns `value.rem_euclid(86_400) as u32`. For positive divisor 86,400,
Rust's Euclidean operation is defined even at i64::MIN and has result
0..86,400, so the u32 narrowing is exact. No abs/negation of the signed minimum
is used. This is a chosen Rust API for a total scalar relation; the original
helper's guard-qualified result writes, opaque callees, fields0/2, raw layouts
and caller semantics remain unimplemented. No clock/calendar units follow.

The original source extracts, from `0x151cbef..0x151cc1e` and the repair
`0x151cc4c..0x151cc56`:

```
M = 0x1845c8a0ce512957; D = 86400
h = floor(s*M / 2^64)
q = (h SAR13) + (unsigned64(h) SHR63)
r0 = s - q*D
field1 = low32(low32(r0) + ((r0 SAR63) AND86400))
```

The existing whole-signed64 algebra proves this field expression is the
Euclidean remainder using `M*D - 2^77 = 12928 < 2^14`, odd M and the explicit
sign repair. The new runner calls those unchanged byte-extracted integer
equations to generate 1,906 expectations. It never generates expected values
from the Rust implementation, `%` or `rem_euclid`. A newly compiled harness
links the actual production library and receives only signed input values;
its output is compared byte-for-byte with the independent oracle stream.
No original node, emulator or concrete CPU interpreter is executed.

The numerical domain is **all i64**, but original writes still require raw
previous status!=1, the original index guard, opaque index-callee EAX!=0,
normal calls/native ABI/live distinct regions and no clobber. In particular
MIN/MAX numeric vectors do not assert that a live caller reaches those writes.
The Rust helper supplies none of these missing original contracts. The
related #648 date/table constructor and #521 clock-prefix attribution are
unchanged and excluded. No private ABI, whole-helper equivalence, node build
or component gate is requested.

## Build and tool provenance

The repository's rust-toolchain.toml research pin is 1.94.1. It is **not a
recovered original node compiler** or its dependency/build provenance.
The observed host compiler is rustc1.94.1 (e408947bf, 2026-03-25), full commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM21.1.8,
x86_64-unknown-linux-gnu; ordinary system linker cc14.2.0 was available.
Only the official rustc/std archives were downloaded into owned /tmp with
verified HTTPS and exact publisher SHA-256 sidecars. Paths/links/licenses and
install hooks were inspected. The isolated prefix uses manifest-listed
payload hardlinks; no installer hook, global configuration or Cargo setup ran.
Upstream toolchain licenses/COPYRIGHT are retained with that distribution;
new source/docs are MIT and no unlicensed inferred source was read/copied.

`TOOLCHAIN.json` records the actual pinned archives/identity and independent
review references. All compiler/test executables, libraries, mutant sources
and raw build outputs remain in owned /tmp; no original binary bytes are
transplanted. Small retained textual results and source/fixture hashes are
bound by this addendum's separate manifest. No changes to original static
MANIFEST or original inputs are needed.

## Reproduce

Use a trusted real rustc1.94.1 and fresh output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/state_dump_remainder_rust.py \
  --rustc /path/to/1.94.1/rustc --output /tmp/remainder-new --controls
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_state_dump_remainder_rust.py -v
make 'PYTHON=python3 -B' doctor verify test catalogue-check reproduce
```

The module README also gives ordinary direct `rustc --crate-type=rlib` and
`rustc --test` commands; no Cargo manifest/dependency is fabricated. Full
actual argv, results and log hashes are retained in `RESULT.json`. One corpus
test runs in each Rust profile, and the independent production comparison uses
the same1,906 distinct scalar inputs in both profiles; these are scalar cases,
not a denominator of recovered functions or all possible input states.

Four actual Rust-source mutants (wrong divisor, signed remainder, u16
narrowing and wrong zero case) compile, produce wrong production-library
values, and fail their compiled semantic tests. Three actual native-operand
counterfactuals reuse the retained M-1/shift/sign controls and change fields
before validation rejects them. Original captures and original negative
results are preserved. Two fresh optimized builds of our own library are
raw byte-identical; this is **not comparison with the original node**.

## Validation status and next gap

The retained component run records actual debug and optimized builds/tests,
source/fixture/compiler/target preservation, compiled semantic controls and
own-build reproducibility. Independent final source review and exact-head
repository checks are recorded in the publication body after they occur;
initial component evidence is not silently relabeled as those later checks.
No hosted-CI, container, original compiler, raw/normalized node identity or
accepted milestone claim is made.

Next: close the remaining native helper/caller contracts and original build
provenance before integrating this expression into a larger reconstructed
helper; do not turn the scalar helper into a total substitute for guarded
native behavior.
