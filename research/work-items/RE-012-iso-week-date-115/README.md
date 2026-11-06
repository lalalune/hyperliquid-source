# RE-012: reconstruct complete node #115 ISO week to packed date

Target Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Foundation utility under
RE-012 startup/helper scope. New independently authored Rust/scripts/docs MIT;
no unlicensed inferred source or captured machine code copied into Rust.

## Gap and result

The previous CE-day/time producer and date/time display contributions establish
Gregorian packed fields and rendering. They do not implement this distinct
ISO-week constructor. This packet resolves the complete384-byte/103-instruction
FDE `0x1628dd0..0x1628f50`: 52/53-week validation, typed weekday conversion,
previous/next calendar year transitions, checked i32-year arithmetic, final
supported-year/ordinal checks and packed result. It supplies real no_std Rust
with no external Cargo packages or clock calls. It is not a re-export of the
CE-day constructor or a thin formatter wrapper.

## Target observations and static closure

`scope.json` freezes the exact full FDE, eleven actual instruction/data anchors
and the400-byte year-flags table at `0x46be3b`. `records.json` preserves original
instructions, full FDE/CIE bytes, actual branches/calls and relocation writers.
GNU/LLVM/Capstone agree on every instruction byte; readelf independently
confirms extent. No masks are used. The additional real function-pointer
writer at `0x64e1b50` is a symbol-free RELATIVE relocation to this FDE. It is a
binding observation, not a whole-ELF caller census or proof of public API name.

The normal body has no unknown called helper: failure edges reach retained
arithmetic/bounds panic slots. Eleven individual real anchor corruptions reject
beneath artifact hashing, plus separate wrong/truncated identity controls.
Those controls protect retained evidence; they are not target execution or
compiled equivalence measurements. Shared calendar/dependency bytes earn no
new first-party-byte credit and no acceptance gate moves.

The year is normalized modulo400 by signed reciprocal division and Euclidean
negative-remainder correction. The actual flags table exactly matches the
stdlib Gregorian relation previously identified, freshly verified here for all
400 entries. The reciprocal C=0x51eb851f satisfies C*400=2^39+112 and
2^31*112<2^39, bounding error below1/400 across the whole signed input domain.
`derive.py` checks those integer premises, without evaluating target instructions.

At `0x1628e0c`, the bit test on0x406 adds a53rd week for exactly those flags
corresponding to January1 Thursday or leap-year Wednesday. The actual
`week-1` unsigned range check rejects week0, excessive weeks and u32MAX before
weekday multiplication or year adjustment. DL supplies a zero-based typed
weekday. Arbitrary raw u8 values are not assumed to be valid original enum
representations; our Weekday enum selects Monday0..Sunday6 explicitly.

The native ordinal relation is week*7+weekday minus its flags-derived anchor.
It is mathematically equivalent to the Monday of the week containing January4
plus7*(week-1)+weekday. An ordinal<=0 decrements the calendar year with checked
arithmetic and adds the previous year's365/366 days. An ordinal beyond the
current year increments the year, again checked, and subtracts that year's
length. Each arm recomputes flags for the resulting calendar year.

Crucially, final supported year bounds[-262143,262142] are checked **after**
those transitions. An adjacent unsupported ISO year can therefore yield a
supported January/December date. A checked i32 increment/decrement can fail
before the final range refusal; Rust exposes `YearOverflow`, not a fabricated
`None` or a wrapped year. Final output packs year<<13, ordinal<<4 and flags;
its masked check rejects ordinal366 in common years. Invalid results return
raw zero in the capture; Rust returns `None` without claiming the original ABI.

## Independent Rust and qualification

Rust uses Gregorian January1 arithmetic and the January4 ISO anchor rather
than transplanting reciprocal/table instructions. It includes private-calendar
math needed by this distinct whole function and a real manifest/lockfile; no
unmerged producer crate or copied producer implementation is used. Original
nominal types, raw enum invalid-input behavior and panic payloads remain open.

Before new Rust existed, `oracle.py` and `freeze.json` fixed317,520 input and
expected rows. Python `datetime.date.fromisocalendar` supplies the actual ISO
conversion in years2000..2399. Exact400-year periodicity extends that independent
stdlib relation to negative and extreme years, then checks target supported
range and i32 crossing. Expected packed flags use stdlib calendar. These are
an independent mathematical oracle, not captured execution data.

All weeks0..54 and u32MAX, every typed weekday, complete positive/negative
400-year cycles, adjacent supported-year boundaries and i32 extremes are
covered. Actual compiled Rust opt-level0 and3 both match every row. Eight
actual compiled mutants exit normally and are detected: missing leap-Wednesday
week53, one-based weekday, incorrect week-one anchor, century leap rule,
swallowed previous-year overflow, shifted supported-year minimum, wrong year
bit shift and wrong weekday flag rotation. First divergent witnesses, compiler,
source/probe hashes and output hashes are retained in `qualification.json`.

Host build, Linux/amd64 release rlib, Clippy all-targets with denied warnings and
rustfmt pass. Commands from repository root after sourcing
`work/environment/new-three-env.sh`:

```sh
python3 -B research/work-items/RE-012-iso-week-date-115/verify.py
python3 -B research/work-items/RE-012-iso-week-date-115/derive.py
python3 -B research/work-items/RE-012-iso-week-date-115/qualify.py --out work/iso-week-replay --rustc "$RUSTUP_HOME/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc"
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-iso-week-date/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-iso-week-date/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --check --manifest-path src/node115-iso-week-date/Cargo.toml
```

Python3.14.5, Capstone5.0.7, GNU2.45, LLVM23.1.4, Rust1.95.0. Only newly
compiled own host Rust executes; Linux produces an rlib. No capture, clock,
OS/TLS service, network node, emulator or instruction evaluator executes.
Native ABI, full calendar parsing/integration and compiled-byte identity remain
unclaimed. Next: connect this conversion to its validated parser callers while
preserving the complete date-domain and failure boundaries.
