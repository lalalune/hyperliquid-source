# RE-014: node115 raw-day packed-date constructor

Target: Linux x86-64 node115,105896032bytes, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Actual FDE0x1628f50..0x16290ca:378bytes/92 instructions. Raw i32 input reaches
an observed u32 packed result or zero. Typed source ABI and callers are unknown.

The independently authored no_std Rust computes a Gregorian400-year cycle,
finds the year using bounded binary search, computes ordinal/flags and preserves
the observed checked-add/year/packed-result gates. It does not copy target
lookup arrays or native instructions, import inferred reference code, invent
the original crate graph or select an arbitrary Chrono dependency version.
The new scalar C export expresses only an integer contract, not NaiveDate ABI.

The new binder authenticates the full115 image, FDE/CIE/body, both actual tables
0x46bcaa(401bytes) and0x46be3b(400bytes), RIP data/call sites, four actual vendor
Locations and unique panic RELATIVE targets. Original source paths point into
`z_vendor/chrono`; the old registry0.4.38 attribution is NOT inherited. Paths
are observations, not proof of the vendor revision. Panic helper bodies and
all caller/source ownership remain outside the implementation claim.

PR2309 owns the ADJACENT constructor0x1628dd0..0x1628f50 and shares the flag
table; that FDE is neither re-exported nor reimplemented here. This PR starts
at its exclusive end, accepts a single raw day rather than its coordinate
inputs, and adds a different complete scalar constructor. Shared flag data is
context, not new global table coverage. Historical own94 work is a lead only;
all new addresses, lookup data, Locations, call destinations and complete body
identity were independently read from115. No94 artifact is needed to reproduce.

## Reproduce

Python3.12/Capstone5.0.6; direct Rust1.94.1 and Linux x86-64 std target:

```sh
python tools/daycount115_rust.py --rustc /path/to/rustc --out-dir work/date-fresh
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-daycount-date/Cargo.toml
HYPERLIQUID_NODE115_DAYCOUNT_RUSTC=/path/to/rustc python -m unittest discover -s tests -p test_daycount115_rust.py -v
```

Use a fresh output directory. Only newly compiled own ELF REL code is
interpreted. Captured input is never run/interpreted and is rejected as an
object or compiler before subprocess dispatch. Actual shared-evaluator
MOVSXD and ROR blockers are recorded with operative inputs; a local scoped
extension models only own-code register MOVSXD32to64 and immediate ROR32by2.
The shared evaluator is unchanged. No networking, signing or node launch.

342074 original-grounded comparisons include both full400-year periods,
signed edges, sampled raw/valid ranges and negative-year calendar checks.
There are zero mismatches, three separately compiled source corruptions and
four operative original-immediate/table counterexamples. Repeated objects
match. A signed reciprocal inequality covers the complete i32 quotient bound;
all native table rows also match mathematical Gregorian generation. These are
same-author static lowerings and arithmetic checks, not independent peer review
or observed execution. See PROOF.md and raw identities in rust-validation.json.

The own381-byte/101-instruction result is not claimed byte-equivalent to the
378-byte target. No aligned-window metric, full-ELF claim or component gate.
Original panic policy, source version, caller/type ABI, full date API and
integrated node remain unclosed. New source/docs MIT; original evidence keeps
its existing rights. See validation.md for exact required-check outcomes.
