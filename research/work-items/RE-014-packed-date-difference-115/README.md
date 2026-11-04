# RE-014: reconstruct the node115 packed-date pair difference

- Component: foundation; RE-001 range validation and RE-014 bounded reconstruction.
- Reference main: 05bc2de303c05525b71e7e257426e741bc66a390.
- Sole target: Linux x86-64 node115, SHA256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- New implementation: src/node115-packed-date-difference, MIT, independently
  authored no_std Rust; no external dependencies or inferred vendor code.
- Result: established scalar normal-return relation, not a production bug fix.
  No progress gate, compiled-byte window or complete-node claim is requested.

## Gap and reuse

Current latency, reference-oracle and heartbeat packets leave the provider
0x162a290 opaque. This closes its bounded integer calculation for future
integration without changing those callers. It does not establish their
calling contracts, timestamp reachability or runtime behavior.

The full GNU export is reused from
[RE-008-node115-heartbeat-query-static](../RE-008-node115-heartbeat-query-static/0x162a290.objdump.txt).
Its SHA256 is
672f97d4247fcddeba679ce66fa61b4fd884d9074490c90527c69cb8118b685c.
Fresh Capstone decoding authenticates the same 112 instructions / 411 bytes.
This is reuse of existing bytes, not a new function/table discovery.
[RE-014-daycount-date-115](../RE-014-daycount-date-115/) already derives the
adjacent date constructor and shared Gregorian tables. That work earns no
second coverage credit here. Historical node94 packets/PRs are not migrated
by name and supply no target-specific equivalence evidence.

## Observations and derivation

All addresses below are ELF linked VAs; file offsets are explicitly labeled.
The FDE at file offset 13365692, CIE 13266648, bounds the entire half-open
0x162a290..0x162a42b range. Its body SHA256 is
4e6a48de01cb915adb84718584904b4aa3546e1507b109ac85851f7e2247d0f5.
There are no unparsed instruction gaps. Inputs are two readable twelve-byte
projections, with u32 loads at offsets 0, 4, 8. Observed scalar results use
RAX and EDX. The Rust structs intentionally make no original ABI/layout claim.

1. The signed date word shifted right 13 gives year -262144..262143.
   Bits 4..12 give ordinal 0..511; low four flags are ignored.
2. The signed reciprocal 0x51eb851f and shift 39 divide by 400, with negative
   remainder repair. Table VA 0x46bcaa supplies leap days for remainder 0..399.
   All 401 contextual bytes equal the mathematical Gregorian sequence; byte
   400 is an endpoint/context check, not an additional index used by this helper.
   SHA256: 25aaa39a8eb1ce46f7d87855944e78f393cc34f6077d322918ad212015ad9f46.
3. Native day-of-cycle zero branches at 0x162a2f2 and 0x162a345 to 0x162a41e.
   Over the raw input domain this is precisely ordinal == 0 and year % 400 == 0.
   Rust returns None at that boundary. Other invalid raw dates are not rejected.
4. For every representable year, native cycle*146097 + remainder*365 +
   table[remainder] equals year*365 + L(year), where
   L(y) = floor((y+3)/4) - floor((y+99)/100) + floor((y+399)/400).
   derive.py exhausts all 524288 years and all 401 table values.
5. Seconds/day 86400 is at 0x162a403; cycle length 146097 at 0x162a3f6.
   Seconds and nanos words are zero-extended. The leap adjustment is -1 when
   left.nanos >= 1e9 and left.seconds < right.seconds, else +1 when
   right.nanos >= 1e9 and left.seconds > right.seconds, otherwise zero.
   The strict comparisons matter, including equal seconds.
6. At 0x162a38d..0x162a3ca, magic 0x112e0be826d694b3, signed high multiply,
   shift 26 and sign correction divide the signed nanos difference by 1e9.
   Its magnitude is at most 2^32-1. Endpoint checks for quotient intervals 0..4,
   monotonic multiplication and the negative sign correction prove truncation
   over that full range. A negative remainder borrows a second and adds 1e9.
   The Rust implementation uses Euclidean division directly.
7. Consequently, for non-boundary inputs the final pair is divmod(T, 1e9),
   T = ((day(left)-day(right))*86400 + left.seconds-right.seconds +
   leap_adjustment)*1e9 + left.nanos-right.nanos.
   The independent fixture oracle uses this wide total nanosecond expression;
   the native-derived comparator instead follows cycle repair and reciprocal
   arithmetic. No arithmetic intermediate approaches i64 overflow on this
   stated domain. For example, even the day contribution stays below 1.7e13
   seconds in magnitude.

The sole call at 0x162a425 reads slot 0x64df848. Actual .rela.dyn file offset
0x135450 binds R_X86_64_RELATIVE addend 0x1681e40. Its location argument at
0x6405408 has a zero raw pointer: relocation at file offset 0x1d640, not that
zero, supplies path VA 0x44583a, length 66. The captured source path ends in
z_vendor/chrono/src/naive/date/mod.rs, line 2334, column 5. These observations
support a date/panic attribution; they do not recover a Chrono revision,
license graph or panic helper/unwind semantics. Normal-return helper closure
is empty; the exceptional helper remains explicitly open.

## Comparison and counterfactuals

The initial oracle was frozen before the new checkout or Rust existed:
[initial-pre-rust-freeze.json](initial-pre-rust-freeze.json),
SHA256 5aa351ab77c3ee9a95cd14a7108a0e4219bc164d79464bd2db7697ee1354d6f1.
It binds 1071744 rows, TSV SHA256
6a8671ad7d0188c6529135f4395d5b1957d306a243fc0413aad7921f4f791eaf:
524288 left-year cases, 524288 right-year cases, 384 ordinal/flag cases,
6400 seconds/nanos cases and 16384 seeded raw-word pairs (seed 0x115162a290).
Large vectors and build products are regenerated, not committed.
The preserved smoke records are examples, not the comparison denominator.

Initial Rust at opt0 and opt3 matches all rows with overflow checks enabled;
three unit tests pass. Independently repeated opt3 host and Linux rlibs are
byte-equal within their respective target/configuration. Linux outputs were
not executed. [initial-rust-qualification.json](initial-rust-qualification.json)
records exact source/tool/build hashes and commands. Later reproductions must
bind their own source hashes; changing the driver does not rewrite that record.

Five actual compiled wrong implementations are rejected on the full vector
set: unsigned year (534362 mismatches), omitted leap days (1064952),
truncated negative nanos (10614), removed zero boundary (9), and non-strict
equal-second leap test (560). Five real instruction-immediate counterfactuals
also change scalar results: nano reciprocal -1, either leap threshold +1,
cycle length +1 and seconds/day +1. Those are arithmetic operand controls,
not execution/emulation of modified captured instructions.

These are same-author, structurally different static arithmetic models,
not independent reviewers or captured-target differential execution.
There is no source/target compiled-code comparison, normalization mask,
full caller integration, original ABI/panic equivalence or whole-ELF claim.

## Reproduce

Use Python 3.12 with Capstone binding 5.0.7 / core 5.0.1280, retained target and
pinned repository tools/elf_index.py and tools/fde_extents.py. The generator
checks their identities, whole target, FDE, body, relocation and reused export.
Output directories must be fresh, ignored work/ or external scratch paths.

```sh
python3 -B research/work-items/RE-014-packed-date-difference-115/derive.py --out work/date-vectors
python3 -B research/work-items/RE-014-packed-date-difference-115/qualify.py \
  --vectors-dir work/date-vectors --out work/date-build \
  --rustc /absolute/trusted/rustc --rustc-sha256 ACTUAL_COMPILER_SHA256 \
  --linker /absolute/trusted/linker --linker-sha256 ACTUAL_LINKER_SHA256
```

The qualifier executes only new Rust host probes and explicitly selected,
hash-pinned trusted build tools. Capture hashes and paths are refused as tools.
It requires the x86_64-unknown-linux-gnu core library already installed.
No downloads, target execution or external services are performed. Run both
under the operator's finite process supervisor on Windows.
The observed compiler is rustc 1.95.0 (59807616e 2026-04-14), LLVM 22.1.2;
linker is the same distribution's rust-lld. Host is Windows gnullvm.
A rerun is labeled post-authorship reproduction, never a new pre-Rust freeze.

Also run the component Cargo commands in its README and official make doctor,
make verify test catalogue-check, and make reproduce. Actual local outcomes
and preserved failures are in validation.json. The mandatory whole tooling
suite remains unrun here because its previous unchanged native Windows input
is unresolved and retry-blocked; this is an unmet check, not a pass/waiver.

Next: integrate with a specific caller only after recovering that caller's
layout, error contract and reachability, and separately authorize isolated
target differential execution if needed. No component gate is advanced.
