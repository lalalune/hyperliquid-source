# RE-012: reconstruct the node115 position integer prefix

Component info-api. Sole target Linux x86-64 node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105896032 bytes.
Independent base05bc2de303c05525b71e7e257426e741bc66a390; unrebased ELF VAs.
This reconstructs established arithmetic under approvedScope, not a new static
discovery: merged #2626 already binds the enclosing position response producer
and `info_server/src/f_types/position.rs` context. Its records, GNU/LLVM exports,
frames and relocation relations are credited and hash-pinned supporting context.
The distinct #2613 async-gate checker ends at the producer's entry. Live issue,
PR and source searches, including exact0x-prefixed addresses, found no Rust
integer-prefix owner; unpublished work and search indexing remain limitations.

## Selected entry, observations and unknowns

Complete enclosing FDE0x2c7fd80..0x2c80666 is2278 bytes/486 instructions,
retained with actual FDE/CIE bytes and agreeing GNU/Capstone exports. It is
static context. The actual interpreted selection is188 bytes/45 instructions:
0x2c7ff0e..0x2c7ffc4 plus narrow DIV0x2c80078..0x2c8007e. All45 starts are
visited. This is one integer prefix, including both division routes; they are
not split into separate contributions. No byte-identity/progress gate credit.

Seed only RAX=raw mark, RDI=raw entry, RSP and [RSP+0x40]=raw nonzero signed
size. Unspecified registers/flags/stack bytes remain unknown; known-bit moves
preserve unknowns from the copied +0x70/+0x110 slots. The evaluator restricts
access to the six touched8-byte stack slots and rejects calls/escaped PCs.
Entry is AFTER opaque lookup: no callback return or producer reachability is
fabricated. The outer zero-size response and arbitrary overlapping memories
are outside the premise. The Rust API enforces this premise with NonZeroI64,
without inventing a native zero-size error.

Original mark-sign or signed-product-overflow stops BEFORE0x2c804dd (M).
Negative nonzero entry stops BEFORE0x2c805e8 (E); product checks have precedence.
Subtraction overflow would stop BEFORE0x2c80502 (S). M/E/S are raw frontier
labels, not native return values, errors or a claim that a handler panics.
No opaque handler is interpreted or replaced.

Normal observations stop BEFORE0x2c800df (absent),0x2c7ffc4 (wide DIV), or
0x2c8007e (narrow DIV). Observe raw RBP product, the stored +0x38 word and,
where present, actual RAX quotient/RDX remainder plus reached width. Raw
unsigned decimal encodes signed bit patterns without normalizing overflow.
The width is an observed internal route, not part of a recovered public ABI.
Normal observations precede layout revalidation, binary64 conversion and
decimal scaling. This library does not claim to produce a final entry price.

## Established arithmetic

Mark must be nonnegative as i64 and size*mark must fit i64 before entry is
inspected. Zero entry explicitly writes PnL0 and absent-price marker, even
when product is nonzero. Other entries must be nonnegative. The saved word is
product minus entry for positive size, or product plus entry for negative size.
Absolute size is its unsigned magnitude, including i64::MIN ->2^63. Entry below
that magnitude produces no quotient; equality is PRESENT. Present entry is
divided by magnitude as an unsigned integer, yielding quotient and remainder
before floating conversion. The32-bit shortcut is used iff both fit u32.

The original S branch is not reached by valid triples: for positive size,
product is in[0,MAX] and entry in[1,MAX], hence their difference is in[-MAX,MAX].
For negative size, product is in[MIN,0] and entry in[1,MAX], so their sum is in
[MIN+1,MAX]. This is an invariant proof, not an executed full-domain claim.
The Rust boundary is retained for correspondence; a missing S observation is
not concealed or manufactured with impossible incoming states.

## Original-first evidence and reconstruction

Commit a9f0d76c1923036fa95f844b0c5c77df95529834 sealed target observations
BEFORE new Rust existed.3328 distinct raw triples:1437 normal,1597M,294E.
Normal routes:601 absent,258 narrow,578 wide. FREEZE.json pins complete input
and expected stream hashes;60 original smoke rows are committed. Eleven actual
byte COW controls change sign/overflow/zero/sign-correction/subtraction,
magnitude/presence or division operands and yield different observations.
The capture is authenticated before/after and never modified.

New MIT Rust and the input-only client are independently authored; no unlicensed
inferred source is read/copied. Existing project ELF View and instruction CPU
are licensed reuse, not original implementation claims. The unchanged CPU uses
known-bit propagation and decodes the actual capture. Normalization, selected
scope and memory premises are explicit above. No captured process, Unicorn,
service, signing, chain, wallet or network-facing runtime is executed.

    python3 research/work-items/RE-012-position-integer-115/freeze.py --output <new-directory> --objdump <GNU-objdump>
    python3 research/work-items/RE-012-position-integer-115/native.py
    python3 research/work-items/RE-012-position-integer-115/build.py --rustc <rustc1.94.1> --output <new-directory>
    python3 -m unittest discover -s tests -p test_node115_position_integer.py -v

Original streams come solely from original instructions, never Rust or a
high-level arithmetic oracle. Source/API types are research choices. Build
and repository check outcomes are retained in rust-results.json and
repository-checks.json when actually observed. macOSarm64 compilation does
not establish original Linux toolchain provenance or compiled body equality.

Floating precision/rounding environment, decimal tables, final response writes,
lookup/asset layout and liquidation helpers remain unresolved. All92 gates
remain false. Next: close the actual asset/decimal path before composing a
full position response. This prefix adds no dependency placeholders or guessed
original Cargo graph.

## Observed Rust results and retained failure

Both rustc1.94.1 opt0/3 builds match all3328 original observations exactly;
optimized own-library repeat is identical. Eleven compiled corruptions produce
242,692,98,81,1339,1339,280,96,541,578,541 mismatches and all fail their ordinary
Rust tests with exit101. Two ordinary tests pass for each unmodified profile.
Second complete build/control run135.890s PASS.

The first attempt77.313s FAILED: the full comparison detected81 zero-entry-PnL
mutant mismatches, but the original60-row sampled smoke did not. Frozen smoke
and original outputs were preserved. A second ordinary test uses ten already-
sealed boundary triples (including nonzero product/zero entry); the entire
build/control matrix was rerun. failed-build.json retains this failure and its
raw-log hash. This is not a claim that the original60 rows alone kill all11.

The freeze command above is historical: run it at the pre-Rust seal checkout.
Current checkouts reproduce the sealed streams using native.py and build.py.

## Scoped repository checks

Six focused tests, rustfmt, Clippy, twelve packet-integrity tests, doctor,
artifact/import/packet verification, catalogue generation/check and actual
inventory reproduction pass (371.839s complete scoped run). Exact commands and
individual timings are in repository-checks.json. Only catalogue steps use
#2655's already-submitted, verified snapshot fix to avoid the measured39.47GB
repeated-read blocker; validation-overlay.json pins both helper hashes. The
baseline helper was restored byte-for-byte before reproduce/commit. That fix
is not duplicated here. These two steps are not unmodified-head catalogue runs.
The successful make steps retain nonfatal macOS xcrun cache-write warnings in
raw external logs; they are not converted to a failed or omitted test.

Earlier full upstream585/584-file passes belong to #2655/#2692. They do not
substitute for this new PR's pending own CI. No local full-suite, hosted-CI,
container, gate-completion or full response equivalence is claimed.
