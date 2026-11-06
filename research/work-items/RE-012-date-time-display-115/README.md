# RE-012: node #115 complete successful date/time display family in Rust

Target Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base main `05bc2de303c05525b71e7e257426e741bc66a390`. Foundation utility
under RE-012 startup/helper scope. Independently authored MIT Rust/docs/scripts;
no copied unlicensed inferred source or transplanted captured instructions.

## Gap, result and boundary

Static PR #2792 identifies the time/date display function used in generated
names, but supplies neither the successful rendering rules nor Rust. The
separate time-producer contribution establishes packed date/time fields; it
does not render them. This contribution recovers the complete successful
output of the date display, time display and combined adapter, including signed
large/negative years, calendar month/day lookup, leap-second display and exact
fractional widths. It adds a real independently buildable no_std Rust crate.

The new renderer uses a fixed ASCII output buffer, not a mock native writer.
Its claimed boundary is successful text for an explicit safe input domain.
Native writer failure calls, partial-prefix granularity, allocation/panic ABI
and raw invalid representations remain open. These important limits are not
hidden by a green build or by calling synthetic output a target run.

## Exact static evidence and reusable context

Seven complete FDEs total3,405 bytes/966 instructions. The primary display
family is1,165 bytes: adapter `0x156d7f0..0x156d838` (72), date display
`0x1628bc0..0x1628dcf` (527), and time display
`0x162a760..0x162a996` (566). Supporting contexts are the existing generic
format consumer `0x1680500..0x16806c0`, signed decimal
`0x1688c00..0x1688d14`, unsigned decimal `0x1688a20..0x1688b1b`, and numeric
padding `0x167e9d0..0x167eec1`. Their2,240 bytes receive no new first-party
credit; this packet closes their selected display call/data relationships,
without claiming all generic formatting semantics or recompiling them identically.

`scope.json` labels each role. `records.json` retains original instructions,
full FDE/CIE records, actual call/branch edges and relocation writers with raw
entries and symbols. GNU/LLVM/Capstone partition every byte identically;
readelf independently confirms FDE extents. No masks are used. Twenty-six
real instruction/data anchors reject separate byte corruption below whole-image
hashing; wrong/truncated capture controls reject separately. These are focused
evidence-integrity checks, not behavioral execution or whole-ELF coverage.

## Observations: date and numeric format closure

The date display extracts signed year with arithmetic shift13. Its lookup
index is `(packed >>3)&0x3ff`, i.e. ordinal*2 plus the common-year flag bit.
Actual733 bytes at `0x46bfcb` convert that index into month/day encodings.
For every valid leap/common ordinal, `derive.py` independently reconstructs
its byte using stdlib Gregorian calendar:

`delta[index]=(month<<6)+(day<<1)+common-index`.

All731 valid index entries plus two leading sentinel bytes match the capture.
The native month/day digit instructions consume index+delta; they emit hyphens
and two-digit decimal month/day. Rust independently walks Gregorian month
lengths instead of copying the captured table into production code.

Years0..9999 emit exactly four decimal digits. Negative years enter the same
special branch as years>=10000 because the native year comparison is unsigned.
The actual template at `0x459860` is `c3 20 00 20 69 05 00 00`.
The format consumer decodes explicit flags and width5, and the actual signed
formatter binds through `0x64e02e0 -> 0x1688c00`. Numeric padding visibly tests
plus flag0x200000 and zero-padding flag0x1000000. Thus the sign precedes zero
padding and the minimum total width is5: year-1 gives `-0001`, year10000 gives
`+10000`, with larger magnitude digits retained. Those examples describe the
proved relation and compiled own-Rust output, not captured execution samples.

## Observations: time, fractional selection and adapter

Time display reads seconds and nanoseconds. It computes hours/minutes/seconds,
adds one to the displayed seconds when nanos>=1e9, and subtracts1e9 from that
fractional word in that arm. The safe API includes the conventional encoding
at second59, producing second60. This does not claim that native constructors
reject every other raw field combination; their complete validation is not
recovered here. The formatter's unusual raw-invalid-hour paths remain outside
our selected safe domain.

Zero fractional nanos emits no decimal point. Nonzero nanos chooses millisecond
precision if divisible by1,000,000, microsecond precision if divisible by1,000,
otherwise nanoseconds. The three actual templates at
`0x46c7a4`/`0x46c7ae`/`0x46c7b8` contain a literal period, numeric zero-pad
flags and widths3/6/9. Thus `.100` remains three digits; it is not stripped to
`.1`. Fractional values after the leap adjustment are handled identically.

The native divisibility shortcuts use odd inverse multiplication, rotate-right
and a threshold. `derive.py` proves their full-u32 meaning without evaluating
captured instructions: write D=2^s*odd, verify inv*odd=1 mod2^32, and threshold
=floor((2^32-1)/D)<2^(32-s). Multiplication by inv and rotation are a bijection.
For every k in[0,threshold], D*k maps to k; hence no other input is accepted.
The actual pairs are (D=1,000,000,s=6,inv=0x68c26139) and
(D=1,000,s=3,inv=0x26e978d5). Hour/minute reciprocal identities are additionally
checked for every second0..86399. These are pure mathematics tied to actual
constants, not an instruction interpreter or a native execution oracle.

The adapter calls the date display, writes one ASCII space, and tail-calls
the time display on the next field. Selected nonzero writer statuses propagate
failure. No timezone marker or underscore is emitted by this display family;
the separate generated-name function performs its later space replacement.
That later normalization is not duplicated or re-credited here.

## Safe Rust API and independent qualification

Private-field `Date` and `Time` constructors explicitly select the supported
safe domain. Date accepts years[-262143,262142] and a valid Gregorian ordinal.
Time accepts seconds<86400, nanos<2e9 and, for nanos>=1e9, second59. Rejection
is additional safe API domain behavior, not native invalid-input equivalence.
The text renderer has no callback and cannot pretend an OS/fmt writer ran.
Its fixed32-byte maximum is date13 + space1 + time18. Native writer refusal
and partially emitted prefix behavior need a separate recovered sink contract.

The crate has no external dependency or build hook. It neither imports an
unmerged producer crate nor copies its production source. It uses independently
authored month walking/ASCII emission; the shared calendar/packed-field facts
are cited as observations, not a fabricated Cargo workspace. Callers can join
logical year/ordinal/seconds/nanos fields once integration is reviewed.

`oracle.py` uses stdlib calendar/datetime and declarative decimal formatting.
`freeze.json` records325,212 expected rows and hashes while the new Rust
directory did not exist. The corpus covers every ordinal across a complete
400-year cycle; negative and large signed years; supported-year/ordinal limits;
every second0..86399 with zero and full precision fractions; all3/6/9-digit
fractional boundaries; conventional leap encodings; domain refusals; and
combined maximum-length output. Positive supported dates also match Python
`datetime.date.isoformat`. Negative/large years use the stated mathematical
calendar extension. No expectation is described as captured output.

Actual opt-level0 and3 Rust both match every frozen row. Eight separately
compiled mutants terminate normally and are detected: large-year sign boundary,
short year padding, wrong positive sign, century leap rule, minute padding,
missing leap-second increment, millisecond padding and adapter T separator.
First witnesses and source/probe hashes are in `qualification.json`.
Initial Clippy rejected manual modulo divisibility style; production switched
to its suggested `is_multiple_of` without altering the frozen oracle. The
original failed lint log is retained under ignored work; final Clippy passes.

Host build, Linux/amd64 release rlib, Clippy all-targets with denied warnings and
rustfmt pass. From repository root after `source work/environment/new-three-env.sh`:

```sh
python3 -B research/work-items/RE-012-date-time-display-115/verify.py
python3 -B research/work-items/RE-012-date-time-display-115/derive.py
python3 -B research/work-items/RE-012-date-time-display-115/qualify.py --out work/date-time-display-replay --rustc "$RUSTUP_HOME/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc"
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-date-time-display/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-date-time-display/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --check --manifest-path src/node115-date-time-display/Cargo.toml
```

Python3.14.5, Capstone5.0.7, GNU2.45, LLVM23.1.4, Rust1.95.0. Only own compiled
host Rust runs; Linux outputs an rlib. No capture execution/emulation, OS/TLS
or clock calls, network, synthetic native writer, compiled-byte match or full
node claim occurs. All gates/byte counts remain unchanged. Next: connect the
producer and successful text output to an established real sink/caller while
recovering native formatting refusal boundaries separately.
