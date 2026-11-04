# Node115 varint size-counter state

RE-005/RE-014, serialization component. Base8fd8db680ec4bfef40996e5616bce3d5156d0b86.
Target node115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Bounded question: what counter state remains at success or the pre-overflow-helper
boundary in the observed u32/u64 varint-size family across its five physical ABIs?

Five complete FDEs are bound in owners.json, including every original byte,
Capstone instruction, actual input/counter roles, fresh RELATIVE Locations and
call slots. Addresses are ELF virtual addresses; file offsets are recorded.
Locations6440bd8 and64b0ef0 both resolve to
z_forks/bincode-fork/src/enc/write.rs:78:9 through relative addend439c31.
No retired94addresses, layouts or completion credit are transplanted.

Observed lengths are1 for values<251,3 below65536,5 below2^32,9 otherwise.
For marker arms the source commits counter+1 before checking the remaining
payload. If the first increment overflows, the counter stays unchanged. If
payload addition overflows, the marker increment remains. Success commits the
full length. The selected raw mode byte in the RCX-value ABI has no effect.
This is a pre-helper state relation, not recovered panic/unwind behavior.

The physical forms are RCX-value/u64 with direct counter; u32 reference with
inline state+10 counter; u32 reference with state+10 pointer to counter; and
two RDX-value/u64 direct-counter bodies. Their original success-tag8 and raw
return-register effects are checked natively, separately from the scalar
projection. The Rust API will not claim their ABI or enum representation.
Qualified synthetic buffers are separate; arbitrary aliases and whole caller
object layouts/reachability are not established.

Before new115 Rust source,83250 physical replay rows were frozen:47250/8550/
8550/9450/9450 by owner. They represent18000 distinct width/value/count triples,
not83250 independent logical states. Five raw mode bytes vary only on the
qualified RCX-value body. Native expectations are emitted by actual instruction
interpretation, checked against separate integer reasoning, and hash-bound in
FREEZE.json. The retired project-authored MIT counter logic preexisted and is
disclosed; no unlicensed inferred source is copied.

Initial small probe passed5.354wall seconds; full pre-Rust freeze passed93.439wall
seconds at10% active duty. Five actual instruction corruptions change results.
Every memory access is bounded; all calls are rejected and evaluation stops
before each original overflow helper. No captured process or helper executes.

Reproduce: `python3 tools/varint_size_state_115_freeze.py work/size115-freeze-new`
with Python3.12.14,Capstone5.0.6 and the authenticated retained115capture.
Output must be new. Generated full TSVs stay in ignored work; hashes/compact
native fixture and all context records are reviewable in this packet/component.
Replay after implementation truthfully reports source existence; semantic
records and hashes must still match the pre-Rust freeze.
No full component gate, byte-equivalence, complete codec or exception claim.

## Rust implementation and actual comparisons

Pre-Rust freeze commit:a45e9f33. Five complete bodies total753bytes and225
instructions. All220non-call instructions are visited; final replay also checks
concrete-decoder/Capstone lengths at all225instruction starts. The five omitted
instructions are the explicit pre-overflow-helper stopping boundaries.

| Start .. end | Value/counter qualification |
| --- | --- |
| 29360e0..293617b | u64 in RCX; direct RSI counter; raw DL mode |
| 58220e0..5822157 | u32 at RSI; inline counter at RDX+10 |
| 5822160..58221d7 | u32 at RSI; counter pointer at RDX+10 |
| 5822850..5822904 | u64 in RDX; direct RSI counter |
| 5822b90..5822c44 | second u64/RDX direct-counter body |

New `src/node115-varint-size-state` contains only the qualified u32/u64 scalar
counter contract; it does not revive the unvalidated retired codec/reader.
This independently authored/project-MIT contract reuses the counter reasoning
from historical PR1920, validated anew against115. No inferred unlicensed
reference code is copied. Both original physical success tags and return
register behavior remain native qualifications, not Rust ABI claims. The own
Result maps only success/pre-helper route and counter state; it does not execute
or reproduce original panic behavior.

Actual pinned rustc1.94.1 e408947bfd,LLVM21.1.8,macOSarm64,edition2021,
opt0/3,codegen-units1,overflow checks and warnings denied. No dependencies,
Cargo workspace/lockfile or recovered original build recipe is invented.
Commands/compiler/source/ownarchive hashes are in build-result.json; local repo
prefix is redacted as <repo>.

Both library profiles match all83250physical replay rows/18000logical triples.
The compiled standalone smoke unit checks25frozen native rows (default test
optimization). Four actual compiled mutants produce2580/77895/82734/261
mismatches and all fail compiled smoke assertions. Own opt3 rlib repeat is
raw-identical. Builder plus fresh native replay passed exit0 in151.622wall
seconds under10% active duty. Full raw TSVs/compiler/mutant logs remain in ignored
work; the hash-frozen generator and compact native fixture are committed.
No target/source byte comparison or normalization is claimed.

Reproduce: `python3 tools/varint_size_state_115_rust.py --rustc <rustc1.94.1>
--output work/size115-build-new`. The external input-only client receives no
expected answers. Native records and frozen stream hashes must match before
compilation. Rustfmt, Clippy library/tests, four focused Python tests, make catalogue,
make doctor/verify/catalogue-check passed exit0 in73.642wall seconds. Focused
Python tests passed in4.774wall seconds. Active capture signatures,29imports/
pins and29packetmanifests/463entries passed before final report additions.
Final packet reporting/manifest edits are verified separately.
The earlier full-suite resource-bound attempt on the same base was incomplete;
it is not reused as PASS. Full make reproduce subsequently passed exit0 in115.729wall seconds, reproducing
both retained115andvisor inventories. Hosted CI is unobserved. The earlier
full make test attempt was on the sibling cache branch sharing base8fd8db68;
it timed out330seconds at file9/77 and is not a current-head or full-suite PASS.
No unchanged expensive full-suite retry is claimed. Nonfatal xcrun cache
permission warnings and optional missing doctor tools are retained; actual
pinned direct Rust builds above passed.
Next: bind the writer/reader callers and exception/trait closure separately
before integrating a complete115codec. Component gates remain false.
