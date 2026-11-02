# RE-014: Rust for node115 signed-pair numeric projections

Component: ABCI/node instrumentation, post-provider scalar values only.
Target node115 SHA256a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
105896032bytes. Basee5c9b6436876b2a4a39daef813171f9879317699.
Freeze c4003a0b (corpus) and a2094d50 (smoke) precede production Rust.
Credit merged#993 and unchanged RE-001-node115-latency-projection. Its existing
static algebra/records establish the relation but supply no Rust component.
New code is independently authored MIT, with no unlicensed reference copied.

## Measured contract and limits

Original ELF FDE0x51c9a70..0x51c9cad,573bytes/143instructions, full body SHA256
a426a545391855818dae5d702ed7e0001862df9cd4e40da48f4591fe53607e58.
All prior native exports, FDE/CIE/source/relocation bindings and original
negative results remain unchanged. The new comparison visits45instructions
across0x51c9b26..0x51c9b75 and0x51c9b9b..0x51c9c06. It stops before observer
calls and does not execute providers, observers, record helper or any other
captured callee.

Each lane takes an explicit raw i64/i32 provider-return pair(w,n). If w<0 and
n>0, the actual integer correction is(w+1,n-1000000000). That branch cannot
overflow either signed width. Convert components separately to binary64, divide
the narrow component by actual1e9, add the wide component, then max with+0.
This operation order matters to floating-point rounding, even though the
correction is exact rationally. All raw pairs yield finite intermediate values;
ordinary nontrapping round-to-nearest binary64 semantics are assumed. FP modes,
status flags, original helper return validity/units and real clocks are unclosed.

The first lane supplies the uncapped value. The second saves the uncapped value
at RSP+0x48 before supplying min(60.0,value) to its observer. The source returns
an own PairProjection{observer_value,saved_value}; it does not reproduce an
original struct ABI. At raw(120,0), these are60.0 and120.0. The later original
reload/store into record-relative+0x18 is credited static evidence **conditional
on the intervening opaque observer preserving the saved slot**. Our evaluator
stops before that call; it does not pretend to prove its memory effects or any
record serialization/persistence. Optional-first-observer guards, tuple source,
anchor/clock policy, complete caller control and ownership/unwind are excluded.

## Reproduced active evaluator blocker

The existing gas evaluator always decodes/executes CVTSI2SD as signed64. The
actual latency sequence also has non-REX F2 0F2A forms that consume signed32.
For lane0 raw(-1,i32::MIN), the old evaluator reports bits4607846626102193450,
while correct signed32 interpretation gives+0. The initial probe failed
exit1 in6.123wall seconds, before any Rust implementation. blocker.json retains
this concrete counterexample; the failure is not relabeled PASS.

Intel documents the default signed32 source and REX.W signed64 extension in
[the official instruction reference](https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf).
Capstone5.0.6 independently verifies the four actual source operand widths
4/4/8/8 and original instruction bytes in conversion-bindings.json. A local
step override handles only these selected F2[48]0F2A encodings, masks to the
actual width and sign-extends accordingly. Unsupported forms reject. Shared
decoder/evaluator modules are unchanged; this is the minimal scoped bridge
needed for this active reconstruction. It is not a generic ISA/tooling PR.
Corrected probeexit0 in5.613wall seconds. No target/helper stub is added.

A plain Machine with empty call/slot/static substitutions evaluates each
post-provider island. Only the measured saved-value stack8bytes are writable;
actual original rodata is read-only. Calls/returns and out-of-window control
are rejected. This explicitly authorized offline Python instruction evaluation
runs no captured process, native binary, Unicorn, real metric/clock/IO/network,
wallet/signature or chain action.

## Frozen population, real builds and controls

2468comparison rows =1234distinct raw signed pairs *2separate lanes. The first
and second real providers are **not** claimed to return the same pair: each
lane is tested independently. The pairs include210Cartesian signed/precision/
correction boundaries plus1024public deterministic pairs. Full input/output
bit-word hashes are frozen before Rust, with no float/output normalization.
Eighteen smoke rows come from that corpus. An initial attempted smoke pair was
absent and raised KeyError before a fixture or Rust was written; the final
fixture uses an already-frozen pair instead. Original history retains this.

Real pinned rustc1.94.1(e408947bfd200af42db322daf0fadfe7e26d3bd1),LLVM21.1.8,
builds direct no_std rlibs at opt0/opt3 with overflow checks and codegen-units1.
Separate input-only clients each match all2468results bit-for-bit;18compiled
smoke rows PASS. Four actual compiled divisor/cap/correction/saved-value
mutants mismatch1094/602/2/602rows and fail smoke(exit101). Own opt3 archives
rebuild raw-identically. Freezeexit0 in62.959wall seconds; buildexit0 in
116.747wall seconds. Host macOSarm64 reproducibility is not original x86-64
code identity or recovered compiler provenance.

Three actual native data/code edits change the divisor, cap and correction
condition. Each changes an observed result and the old full binding rejects it.
Long raw corpora and build products regenerate outside Git; build-result.json
records exact commands/source/compiler/output identities with private path
spellings replaced only. There is no fabricated Cargo workspace/dependency graph.

## Reproduce and remaining validation

From repository root with authenticated inputs, Python3.12.14, Capstone5.0.6
and actual pinned Rust tools:

    python3 tools/node115_latency_pair_rust.py --rustc "$RUSTC" --output /new/output
    python3 -m unittest tests.test_node115_latency_pair_rust -v
    "$RUSTFMT" --check --edition 2021 src/node115-latency-pair/lib.rs src/node115-latency-pair/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node115-latency-pair/lib.rs --emit=metadata -o /new/lib.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node115-latency-pair/lib.rs --emit=metadata -o /new/test.rmeta -D warnings
    make doctor verify test catalogue-check reproduce

Output must be new. Identity, full records, corpus hashes, selected bytes,
operand widths, controls and smoke-copy equality are checked before compiler
admission. Five focused tests PASS71.675wall seconds; pinnedfmt and Clippy library/test
PASS; fresh catalogue-check PASS. Combined exit0 in120.120wall seconds, with
nonfatal xcrun warnings retained in validation-results.json.
Signed-input/import/inventory checks reuse completed#1831 only within explicitly
unchanged dependencies; this is not new-code or whole-suite verification.
Full make test remains incomplete and upstreamCI pending; queued is not PASS.
All component gates, catalogue inputs and byte credit remain unchanged.

Local jobs remain serial10%active-wall duty and bounded; setpriority is
unavailable and exact aggregateCPU percentage is not promised. Next close the
actual pair provider and observer's saved-slot preservation before connecting
the scalar source to a real metrics/record path.
