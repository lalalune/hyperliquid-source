# RE-004: complete byte-indexed mixed-width lookup pair

The foundation dual-table and mixed-width-dual-table packets bound two
30-byte leaves, but examined only four/eight entries and supplied no Rust.
This contribution reconstructs both as one coherent safe `no_std` component,
closing every byte-indexed read and both full RAX/RDX results. The overlap
between u64 and i32 data windows is preserved, rather than assuming separate
source-level tables or limiting inputs to the previously inspected heads.

- Task/component: RE-004 / foundation, a bounded value reconstruction.
- Target: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Full FDEs: `[0x299e280,0x299e29e)` and `[0x29d7fc0,0x29d7fde)`.
- Fresh origin/main base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Changed paths: `src/node94-mixed-lookup-pair` and this evidence packet.
- Authored independently with OpenAI Codex; exact model identifier unavailable.
  New source/prose is MIT. No inferred reference implementation was copied.

## Exact relation and data closure

For each member, the low input byte j indexes one unsigned qword and one
signed i32. RDX is the qword unchanged. RAX is linked i32-base plus actual
load bias plus the sign-extended offset, modulo 2^64. The first member's
bases are `0x3f7918` / `0x3f7ba0`; the second's are `0x4024a0` / `0x402728`.
The new member selector chooses the original entrypoint; it is not an
original machine argument. Returned addresses are numeric and never followed.

[PROOF.md](PROOF.md) covers every possible raw u64 input, the ignored upper
56 bits, signed extension, modulo address arithmetic and array safety.
The library has no dependency, allocation, unsafe block, domain cap or
fallible path. It implements the shared proved algorithm over separately
bound scalar constants, without inventing an original library/type identity.

Each qword window contains 256 reachable entries, exactly 2,048 bytes.
The corresponding 1,024-byte i32 window begins 0x288 bytes into it and ends
at relative 0x688, wholly inside that same physical window. The packet
retains all 4,096 unique `.rodata` bytes and all decoded numeric entries.
All 80,300 RELA records were scanned for any partial or complete overlapping
writer: none touches either data window. Runtime contents therefore require
only the explicit unchanged-read-only-data premise; no partial relocation
is omitted or guessed. A 256-entry reachable window is not a claim about
logical table length. Qword values and resolved addresses remain opaque.

## Bodies, callers and decoder distinction

Both full 30-byte/seven-instruction bodies, actual FDE/CIE records, padding,
address successors and frame-order neighbor are bound. There are no helper
calls, branches or external dependencies inside either leaf. Full four
caller FDEs cover 15,600 bytes / 3,161 instructions and anchor all seven
raw E8 candidates. No E9 candidate or relocation naming either entry was
found. This is not a complete indirect-reference census or caller semantic
reconstruction; caller exception-table contents and downstream use are not
leaf dependencies or recovered behaviors.

GNU and Capstone agree on complete boundaries. Apple LLVM agrees on the
leaves and every caller boundary except its display split at `0x167aa04`:
it prints LOCK (`f0`) separately from DEC (`48ff08`). The verifier checks
and joins exactly those two raw rows to compare the same `f048ff08`
instruction. This is one explicit display-boundary normalization with no
byte/operand mask. Both unmodified raw outputs remain available.

The initial strict-boundary check failed on that display split before
static freezing or Rust implementation. `initial-static.json.gz` preserves
the failing verifier and exact stdout/stderr diagnostics. The corrected
verifier then froze the full evidence; 59 corruption controls reject body,
FDE/CIE, padding, data endpoints/overlap boundaries and caller drift even
with Python `-O`. No native value qualification failed.

## Independent frozen expectations and native results

Before the Rust directory existed, `oracle.py`, `static.json`, raw data,
inputs and outputs were frozen/hash-bound. The oracle decodes raw-byte
polynomials, applies explicit two's-complement subtraction and one unbounded
address expression. The source uses compiled typed scalar arrays, widening
and staged wrapping additions. `input_only_driver.rs` accepts only member,
raw index and load bias; expected outputs are never passed to the client.

The 15,200 cases cover all 512 member/index pairs with multiple independent
high-bit patterns and biases, all 64 one-bit register positions, negative
and nonnegative offsets, and constructed wrap outputs zero/one/u64::MAX.
There are 5,236 negative-offset and 9,964 nonnegative-offset cases.

Final qualification passed:

- Opt0 and opt3 compare every case exactly, without output masks. Repeat
  runs give 60,800 matching full-RAX/RDX observations.
- All 44 actual compiled mutant runs produce value mismatches, covering
  index width/order, member-table selection, qword/offset byte order,
  signedness, base constants, bias, wrapping and return narrowing.
- Three units per profile, malformed-input/member-descriptor refusals and
  comparator corruption controls pass.
- Four repeated artifacts, rlib/client per profile, are byte-identical
  without normalization.

`native-result.json` binds source (including all recovered scalar tables),
actual compiler/linker and expected streams, with counts and first mutant
witnesses. `native-commands.json` records all 156 invocations. All 312 raw
stdout/stderr streams are hash-bound, losslessly deduplicated in
`native-streams.json.gz`, and decoded again to verify equality. Gzip uses
level 1 and mtime 0; no failing stream was dropped.

## Reproduce

From the repository root, with unchanged materialized inputs and a fresh
native output directory:

```sh
python3 -O research/work-items/RE-004-mixed-lookup-pair-rust-94/verify_static.py
python3 -O research/work-items/RE-004-mixed-lookup-pair-rust-94/verify_rust.py \
  --rustc "$HOME/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc" \
  --out work/mixed-lookup-pair-rust/replay
python3 tools/foundation_dual_table_lookup.py \
  --check research/work-items/foundation-dual-table-lookup-94/evidence.json
python3 tools/foundation_mixed_width_dual_table_lookup.py \
  --check research/work-items/foundation-mixed-width-dual-table-lookup-94/evidence.json
python3 -m unittest tests.test_foundation_dual_table_lookup \
  tests.test_foundation_mixed_width_dual_table_lookup -v
make doctor
make verify
make catalogue-check
make reproduce
```

Rustc is actual 1.94.1, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`,
SHA-256 `b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`,
LLVM 21.1.8. The recipe explicitly selects aarch64-apple-darwin, edition
2021, warnings denied, codegen-units=1, overflow checks enabled, opt0/opt3,
`/usr/bin/cc` and a recorded source-path remap. This is a native host value
component, not a build of the original x86 binary. No speculative Cargo
workspace, dependency or lockfile is introduced.

Raw listings were generated with `/opt/homebrew/opt/binutils/bin/objdump -d
--insn-width=16 --start-address=START --stop-address=END artifacts/node/94/hl-node`
and `/usr/bin/objdump -d --start-address=START --stop-address=END
artifacts/node/94/hl-node`, separately for both member FDEs and all four
caller FDEs listed in `verify_static.py`. Actual versions were GNU binutils
2.47.20260726, Apple LLVM 17.0.0, Python 3.14.3 and Capstone 5.0.7.

`checks.json`, `checks-commands.json` and the lossless check-stream archive
record the completed focused/global checks and tool versions: both predecessor
checkers, all 24 legacy tests, doctor/verify/catalogue-check/reproduce and
rustfmt passed. `overlap.json`
binds the fresh 159-open-PR, 100-recent-merged, zero-open-issue inventory
and current-source check; no active overlapping implementation was found.

## Limits and baseline

Original correspondence requires unchanged original `.rodata`, actual
load bias, ordinary memory and normally completing original reads/return.
Arbitrary numeric biases need not describe possible module mappings.
No claim covers runtime patches, MMIO, faults, concurrent mutation,
original ABI/control, flags, other volatile registers, pointed-string
identity, original compiler or original compiled-byte identity.
No captured instructions, instruction emulator, live node or chain ran.

The separate shared baseline at source base `56c0ec67` attempted 971 files /
15,462 reported tests / 69 skips. Its original `make test` exited 2 solely
for three disk-full errors; all 20 tests in the affected files passed
isolated retry. No successful full-sweep rerun, per-head full suite, skipped
Linux qualification or hosted success is claimed. Pins, predecessor packets,
catalogues and whole-component progress gates remain unchanged.
