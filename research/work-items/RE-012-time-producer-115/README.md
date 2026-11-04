# RE-012: reconstruct node #115 complete time producer and CE packed date

Target Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Foundation utility under
RE-012 startup/helper scope. Independently authored MIT Rust/scripts/docs;
no unlicensed inferred source or captured machine code copied into Rust.

## Gap, result and exact scope

PR #2792 establishes the generated-name call's time source and formatter
bindings but leaves its packed calendar construction and full-domain semantics
unreconstructed. This contribution supplies real dependency-free `no_std` Rust
for the complete pure mathematics behind `0x1629690..0x1629795`, including the
actual CE-day constructor at `0x64dfff0 -> 0x1628f50..0x16290ca`. It recovers
full supported positive/negative year and packed-field behavior, rather than
using an opaque date stub or inventing a clock result.

`from_clock_read` begins after a successful OS clock call; seconds/nanoseconds
are explicit inputs. `from_ce_day` independently implements the constructor.
The Rust deliberately uses Gregorian arithmetic and a year search rather than
the target's optimized reciprocal/table algorithm. Both expose safe logical
results and errors; source-built instruction equality, native layout and panic
ABI are not claimed. There is no new Cargo dependency or copied Chrono source.

## Static evidence and observed boundaries

Four complete FDEs total1,038 bytes/262 instructions: time producer261 bytes,
CE-day constructor378 bytes, clock wrapper201 bytes at
`0x5c842e0..0x5c843a9`, and difference198 bytes at
`0x5c84210..0x5c842d6`. Raw GNU/LLVM/Capstone partitions agree. Native readelf
independently checks all extents. `records.json` retains instruction bytes,
FDE/CIE records and actual relative/dynamic relocation writers, without masks.
Eighteen real instruction/data anchors reject separate corruptions beneath
the whole-image digest check, plus wrong/truncated identity controls.
These are evidence-integrity checks, not native behavioral execution.

At `0x162969d`, EDI=0 selects the clock boundary. Actual slot `0x64e1248` is
`clock_gettime`; the wrapper rejects raw nanoseconds >=1,000,000,000 and OS
failure. The producer forms a zero seconds/nanoseconds origin and invokes the
retained timespec-difference helper. A pre-origin result reaches its failure
branch before calendar arithmetic. For successful nonnegative seconds, it
splits by86,400, adds719,163 to the day count, checks the CE-day i32 range,
and invokes the complete date constructor. A rejected date reaches a failure
helper. Normal output stores three dwords: packed date, seconds of day, nanos.
These role names follow instructions and actual display consumers; no original
Rust nominal type or struct ABI is asserted.

The safe API maps invalid nanoseconds, pre-origin seconds and date range to
explicit errors. It does not reproduce OS side effects or native panic data.
A clock_gettime failure is outside the successful-read input boundary, rather
than a fake read manufactured by a test. The standalone CE-date API includes
negative years; the producer itself rejects pre-Unix-origin clock reads.

## Complete calendar mathematics and real captured tables

The constructor checks signed CEday+365 overflow, then decomposes into a
146,097-day Gregorian cycle using Euclidean correction. Its year estimate is
corrected with the actual401-byte leap-delta table at `0x46bcaa`. The 400-byte
flags table at `0x46be3b` supplies the low packed flags for the cycle's year.
`derive.py` proves both tables exactly from stdlib Gregorian identities:

- Delta(y)=ceil(y/4)-ceil(y/100)+ceil(y/400), y=0..400.
- Flags(y)=nonleap*8 | (((weekday(Jan1)+5) mod7)+1), y=0..399,
  where Python's weekday convention uses Monday0.

The code reconstructs absolute year, rejects outside [-262143,262142], and
packs `(year<<13)|(ordinal<<4)|flags`. The final masked check rejects ordinal366
in common years while allowing it in leap years. A rejected date returns raw
zero; no valid constructed date in this range packs to zero. Rust returns
`None` for that logical boundary and also exposes the observed fields.

The reciprocal constants are checked with explicit whole-domain error bounds:
C=`0x1845c8a0ce512957`, C*86400=2^77+12928, and
(2^63-1)*12928<2^77. For nonnegative seconds, the reciprocal error is strictly
less than1/86400, so its floor quotient equals integer division. For the signed
CE cycle, `0x396b06bd*146097=2^47+31405` and 2^31*31405<2^47; signed truncation
plus the observed negative-remainder correction gives Euclidean division.
The remaining year estimate and previous-year correction are checked for all
146,097 cycle remainders against stdlib-calendar year boundaries. These are
mathematical identities derived from static branches, not a captured-code
interpreter and not an independent native execution oracle.

## Independent frozen qualification and actual results

Before the new Rust directory existed, `oracle.py` and `freeze.json` fixed
292,941 input/expected rows and hashes. The oracle uses stdlib `calendar` to
accumulate a 400-year cycle and bisect within that cycle, independently of the
Rust's direct whole-range year search. Ordinary positive Unix reads are also
cross-checked against stdlib UTC `datetime`. Negative and beyond-datetime years
use the explicit mathematical Gregorian extension. Neither an OS read nor
captured binary output is asserted.

The corpus includes every day in one positive and one negative complete cycle,
minimum/maximum supported years and adjacent failures, zero/negative CE days,
i32 extremes and checked-add boundaries, epoch/day/month/leap transitions,
pre-origin i64 values, i64MAX seconds, and nanos0/1/999999999/1000000000/u64MAX.
Both opt-level0 and3 actual Rust rlibs/probes match every frozen result row.
Seven separately compiled mutants terminate normally and diverge: shifted
minimum year, wrong century leap rule, truncating negative-year division,
wrong ordinal bit shift, weekday rotation, epoch-day offset and allowing
one-billion nanoseconds. First witnesses and source/probe hashes are retained.

A draft `derive.py` extension accidentally shadowed its retained record variable
with a cycle integer and raised TypeError. The variable was renamed; its
identity/table/math checks then pass. This did not change production Rust or
the pre-Rust frozen calendar expectations. The successful final qualification
and all compiled mutants are actual observed results, not inferred success.

Host Cargo build, Linux/amd64 release rlib build, Clippy all-targets with denied
warnings and rustfmt pass. The manifest/lockfile has no build hooks or external
packages. From repository root after `source work/environment/new-three-env.sh`:

```sh
python3 -B research/work-items/RE-012-time-producer-115/verify.py
python3 -B research/work-items/RE-012-time-producer-115/derive.py
python3 -B research/work-items/RE-012-time-producer-115/qualify.py --out work/time-producer-replay --rustc "$RUSTUP_HOME/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc"
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-time-producer/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-time-producer/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --check --manifest-path src/node115-time-producer/Cargo.toml
```

Python3.14.5, Capstone5.0.7, GNU2.45, LLVM23.1.4, Rust1.95.0. Only newly
compiled own Rust host probes execute; Linux outputs an rlib, and no capture,
OS/TLS/clock/network service, emulator or instruction evaluator runs. No gate
or byte-equivalence count moves. Next: join this packed-value contract to the
complete date/time display family and the actual caller after validating their
output/failure boundaries.
