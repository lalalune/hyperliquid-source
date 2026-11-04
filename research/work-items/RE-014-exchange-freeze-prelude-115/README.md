# Node115 exchange freeze/periodic preparation prelude

RE-014/RE-001, component exchange. Base8fd8db680ec4bfef40996e5616bce3d5156d0b86.
Target node115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Question: how do the fixed cadence, past-target checks, raw outer tag and
secondary cadence decide the helper-free preparation prelude's route/flags?
This does not recover a complete exchange method or snapshot API.

Three complete FDE-described owners at2d25620..2d275c3,5a07ec0..5a0871c and
5a08720..5a08f7c are bound by SHA/FDE/full Capstone extents in owners.json.
These owners total12379bytes; only145selected instructions are interpreted.
Addresses are linked Linux x86-64 ELF virtual addresses, file offsets recorded.
Six cold boundaries resolve fresh RELATIVE Locations to
l1/src/exchange/exchange.rs:607:17. This is source association, not original
function names or complete ownership. Source field/argument types stay opaque.
The preloaded scalar named height is read at context+28 by the actual prefix;
context comes from outer+450. It is not independently typed as a block height.

## Observed ordering and projection

The fixed10000predicate is checked first. On nonfixed inputs only, raw freeze
tag1 with target<height reaches the first cold boundary. The raw outer dword
then selects the sentinel-word path exactly when it equals2. That path stores
8000000000000000 in the output's first word; the projection stops before its
cleanup jump and does not claim a completed return or original enum ABI.

Other outer tags encounter a second tag1/past-target check. Thus a fixed
counter with an already-past target can reach sentinel handoff for outer2,
while another outer tag reaches the second cold boundary. This differs from
the retired94scalar admission interface, which tested a target before periodicity.
No one-to-one mapping of original source functions is asserted.
At a fixed counter and outer2, the selected code needs neither freeze field;
a native missing-memory experiment confirms that ordering in all three lanes.
The scalar Rust interface will not reproduce memory/argument evaluation order.

Preparation flags are one active byte each: fixed-or-freeze-equal requested,
and freeze-tag1-and-equal. Upper temporary padding is excluded from this scalar
projection. The basic lane skips preparation when request=false. The two other
lanes can still reach preparation when the scalar is divisible by a secondary
configured cadence (context+39c8 or+4538). Their division dispatcher uses32bits
when both operands fit,64bits otherwise, with zeroed high dividend. With a
positive divisor both implement the same unsigned remainder predicate.
Zero divisors, traps and caller/configuration reachability remain unclosed;
the secondary Rust API will explicitly take NonZeroU64, without a max(1) clamp.

The three preparation calls and all cold helper calls are stopping boundaries.
No helper is stubbed or executed. Later freeze/periodic label selection is only
supporting static context; no filesystem write or whole-callee behavior inferred.

## Arithmetic and active tooling blocker

The fixed predicate computes ror64((h*u) mod2^64,4)<floor(MAX/10000)+1,
where625*u=1 modulo2^64 and10000=16*625. If h=10000*k, the wrapped product is
16*k and the rotation is k, within that bound. Conversely a rotated k within
the bound is below2^60, so reversing rotation gives16*k and h=10000*k without
overflow. This proves the fixed predicate over all raw u64 values; comparison
sampling is a separate concrete check, not the mathematical proof itself.

The shared concrete evaluator rejected ROR(kind1). Initial/strict probes failed
4.280/5.077wall seconds at that instruction. A task-local adapter supports only
ROR64 counts4and3(the real mutation control); other rotate domains fail closed.
It preserves modeled ZF/SF, sets CF from result MSB and leaves OF undefined for
these counts, following Intel SDM Vol2B RCL/RCR/ROL/ROR section4-529:
https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf
Shared tooling is unchanged. Only already-established entry registers are
initialized; other registers stay unknown. Strict supported probe passed4.818s.

## Pre-Rust freeze and reproduction

81646physical rows represent51668distinct inputs across two logical classes;
rows by lane21690/29978/29978. The two secondary lanes have different actual
state fields but share the selected scalar rule. Six actual instruction
corruptions are detected. First sweep failed114.730s because one witness used
a different duplicated outer-tag compare, leaving its changed instruction
inactive. The witness was corrected, control-only probe passed28.654s, and
full corrected freeze passed130.307s. Failed logs are preserved in ignored work.
No115Rustsource existed at this freeze; retired94admission logic preexisted and
is explicitly disclosed. No unlicensed inferred source copied.

Reproduce: `python3 tools/exchange_freeze_115_freeze.py work/exchange-freeze-new`
with Python3.12.14,Capstone5.0.6 and the authenticated115input. Output must be new.
Full generated TSVs stay in ignored work, bound by FREEZE.json hashes; compact
native smoke rows will accompany the Rust component. Native expected results
come from selected instructions, not production Rust or a helper stub.
No captured process, helper, networking, chain or wallet execution. No code-byte
normalization, identity/whole-node claim, byte credit or component gate change.

## Independent Rust and comparisons

Freeze commit15b4cfe8 predates new115Rust. The standalone no_std component
src/node115-exchange-freeze-prelude exposes two selected logical classes. Own
enum names are branch labels, not original ABI. The secondary API explicitly
requires NonZeroU64. A scalar API cannot reproduce skipped input loads, pointer
aliases, original frame layout or argument-evaluation order. Low-byte flags
are the declared projection; the freeze's term padding describes excluded
bits only, not proof of original types or their later use.

Actual rustc1.94.1 e408947bfd/LLVM21.1.8,macOSarm64,edition2021,overflow checks,
codegen-units1,opt0/3,warnings denied. There are no dependencies, fabricated
Cargo graph or lockfile. This is a research compiler pin, not a recovered
original115build recipe. Commands/source/ownarchive hashes are in build-result.json
(local repository prefix redacted as <repo>).

Both library profiles match all81646physical rows/51668two-class inputs.
The default compiled smoke checks23already-frozen native rows. Five actual
compiled mutants yield102/9723/54/306/1968mismatches and all fail smoke checks.
Own opt3 rlib repeat is raw-identical. Builder/native replay PASS198.485wall
seconds at10% duty. Initial fixture setup selected a cadence7 row outside the
frozen matrix, raising KeyError before compilation. It was replaced with an
already-frozen cadence2 row; no native expectation was added after Rust.
Original generated TSVs/compiler/mutant logs and failed attempts remain in ignored work.

Reproduce: `python3 tools/exchange_freeze_115_rust.py --rustc <rustc1.94.1>
--output work/exchange-prelude-new`. The separately linked client reads inputs
only; target records and pre-Rust stream hashes must match before compiling.
No target/source machine-byte comparison or operand normalization claimed.
Rustfmt, Clippy library/test, initial four focused Python tests, make catalogue,
make doctor/verify/catalogue-check passed exit0 in78.378wall seconds. Active
signatures,29imports/pins,29packetmanifests/464entries passed before final report
additions. A final five-test run including direct RIP label/selector binding
passed5.022wall seconds (limited command6.133s). The test binds6-byte freeze and
8-byte periodic data plus the post-helper selector in both secondary owners;
this is conditional static support, not helper or filesystem behavior.
Final report/manifest edits receive separate packet verification. Full make test remains
incomplete after the earlier same-base sibling attempt; no PASS is inferred.
Shared inventory reproduction may be reused only for its unchanged dependency
closure, never as exact-head/full-suite validation. Hosted CI is unobserved.
Next: close callers/continuations and the preparation helpers before composing
whole exchange execution or snapshot behavior. All component gates stay false.
