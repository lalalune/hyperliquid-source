# RE-014: fresh node115 u64-key hash and its real writer dependency

Component: foundation / numeric-selector lookup dependency. Partial #115
reconstruction, not a complete selector, collection or protocol implementation.
Target Linuxx86-64 node115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base8fd8db680ec4bfef40996e5616bce3d5156d0b86. New material MIT; original
captures/imports/rights unchanged. No unlicensed inferred source is used.

## Concrete gap

Main's RE-001-node115-numeric-selector explicitly leaves the hash/table helpers
unclosed. Native caller46aa570 supplies two seed qwords from context+110/+118
and a computed integer key in RDX to47172c0, twice on its multi-row route.
The bounded question here is the raw returned u64 for that fresh eight-byte
input and those supplied seeds. It does not close the table lookup3ed2280,
whole selector, caller context values or public key/asset interpretation.
All addresses are unre-based ELF VAs; layout offsets above are hexadecimal.

The primary FDE47172c0..4717433 is371bytes/91instructions. Its actual CALL
at471733b enters the complete471-byte/141instruction writer45927a0..4592977.
The caller FDE46aa570..46aa753 is retained as unexecuted context. The writer
is interpreted only with fresh state and length8; its general streaming,
leftover bytes and arbitrary-length API are not reconstructed by this result.
No imported calls, external data, callback substitute or copied machine-code
candidate is needed. Authentic original CALL and RET manipulate a bounded
synthetic stack; the original artifact is never launched.

## Source chronology and actual evidence

Before new Rust exists, freeze.py authenticates the original capture, interprets
all distinct stimuli, checks complete FDE/CIE records and independent GNU /
Capstone byte rows, and retains original instruction exports. Expectations
come only from original instruction observations, never a Rust/high-level hash
model. FREEZE.json binds counts, visited addresses and input/output hashes.
Original full streams stay under ignored work/; target-smoke.tsv retains real
selected observations. The Git freeze commit is recorded in rust-results.json.

The maintained interpreter initially failed at actual writer ROL64, reported
in hl-u64-key-hash115-probe.log (exit1,0.549s). A minimal packet-local ROL64
handler unblocks this active RE task; it preserves ZF/SF, defines CF and defines
OF only for count1. It reuses the pattern from our existing MIT ROL16 handler;
the shared interpreter is unchanged. The corrected three-case probe passed
0.548s. Raw failure and corrected outputs remain preserved. No other opcode
or helper semantics is replaced.

Four actual original-byte COW controls change an initialization constant,
input length, the real writer's rotation and finalization XOR. Each must change
the returned word on the same input; the read-only capture is unchanged.
Unknown registers/flags, an escaped branch, unexpected call or memory access,
and a step-bound failure remain errors. Only the raw returned word is compared;
stack padding, unspecified register/flag state and original Rust layout are
not part of that value contract. Native stack writes stay within the declared
bounded arena, including spill/reload paths.

## Scope limits and next step

Research uses Python3.12.14,Capstone5.0.6,owned GNUobjdump and the pinned
rustc1.94.1/LLVM21.1.8 macOSarm64 research compiler. That compiler is not an
original Linux node build recipe. Exact commands and actual results belong
in validation.txt; the independently authored Rust/input-only driver and its
compiled corruption controls are bound by rust-results.json after collection.
All92 component gates remain false. No full-module byte equivalence or native
process/Unicorn execution is claimed. All-state PR and prior-submission checks
preceded selection; different addresses alone do not establish unique work.

Next close the table/probe helper and caller context provenance before assigning
selector membership or protocol behavior. A match of this fresh fixed8 hash
cannot transfer old fixed20/#94 observations or qualify generic writer inputs.

Original freeze v1 failed24.065s because its selected writer-rotation control
changed an unvisited partial-state branch, leaving the fresh8 result unchanged.
No new Rust or frozen output existed at that failure. The final control chooses
an actual visited ROL13 instruction; full original collection reran and passed
23.782s,1622distinct triples,41retained smoke rows,4effective code controls.
The failed log is preserved; no comparison denominator was reduced.

## Dependency attribution and refreshed base

The round structure resembles public standard-library hash machinery. This is
a dependency-like value reconstruction serving the private selector call path,
not a claim that the hash algorithm is private first-party logic. Exact crate,
source revision and original compiler provenance are not yet identified. Its
foundation allocation and source-area count are inventory only; no first-party
compiled-byte comparison or acceptance gate is credited. Original collection
base remains8fd8db68; integration is refreshed against main05bc2de3, preserving
the pre-Rust freeze commit and original failed/successful receipts.
