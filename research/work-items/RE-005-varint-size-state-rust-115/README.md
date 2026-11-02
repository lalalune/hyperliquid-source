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
