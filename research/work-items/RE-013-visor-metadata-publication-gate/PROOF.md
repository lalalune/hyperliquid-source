# Conditional metadata-to-publication relation

The claim is conditional and local: a newly copied, non-tag-2 metadata result
produces a byte f in {0,1}. If its download result reaches the selected
publication call, publication can reach its operation calls only through the
download's explicit 32-byte equality branch. The alternative branch that skips
that comparison returns f XOR 1 = 0 and is rejected by publication. This does
not establish what the 32 bytes represent, signature verification, quorum
membership, or successful filesystem effects.

## Premises and scope

T means raw u64 `0x8000000000000000`. M, D and P name the metadata output,
download output and publication path object. S names each function's RSP after
its prologue; separate functions have separate S. Offsets are raw byte offsets.

1. Enter each function normally, with accessible, nonwrapping, suitably aligned
   storage for every executed load/store. Metadata input byte is 0..3. Its other
   input fields, selector-dependent tables, helper output records and optional
   pointers are valid for the executed path. The four-way dispatch has no local
   bounds check; this is not a malformed-input safety result.
2. Input/output objects and live frames do not overlap in ways that alter the
   displayed relation. Helpers preserve callee-saved registers and live caller
   storage except the particular output region passed to them. No reentrancy,
   concurrency or retained pointer changes those live fields. These assumptions
   include formatting/logging/drop calls and helper-owned allocations. The
   imported `memcpy` supplies its ordinary byte-copy relation on valid disjoint
   spans; a file relocation binding is not proof of runtime interposition.
3. All executed calls return normally for the stated result. Helpers may fail,
   trap or unwind instead; the proof makes no progress, resource-release or
   exceptional-path guarantee. A graph's call-return edge is conditional.
4. The composed fresh-result claim takes the metadata caller's non-2 branch
   and its subsequent cache/copy corridor. On tag 2, an older cached record may
   instead feed download. Its bit provenance is a separate premise, not a new
   result of this metadata invocation.

The three complete FDEs are metadata `0x415620..0x416cce` (5806 bytes/964 rows),
download `0x4148b0..0x4155a2` (3314/627), and publication
`0x416f30..0x41718a` (602/157). Three caller corridors add 733 bytes/130 rows.
The actual caller FDE `0x5e44c0..0x5ea1c1` is retained as raw unwind provenance,
not decoded here in full or claimed as a complete lifecycle theorem.

Both native decoders cover every selected byte and agree on instruction
boundaries without masking. `flow.tsv` retains every local control-transfer
row; `calls.tsv` retains every direct/indirect call, including landing bodies.
The graph audits ordinary structural edges only. Raw FDE/CIE and header links
establish scope, not source function names or a runtime unwind contract.

## Where the bit comes from

Metadata saves output M in RBX and input EDX in R12D. `0x41563a..0x41564b`
uses input byte0 to index four signed offsets at `0x7bcf8`:

| Mode | Target | Ordinary non-error result | Stored f = M[0x129] |
|---:|---|---|---|
| 0 | `0x41564d` | outer word0=0; companion M[0x128]=1 | 0 at `0x415a50` |
| 1 | `0x415f00` | outer word0=1; companion=0 | 0 at `0x41682e` |
| 2 | `0x415a5e` | outer word0=0; companion=1 | R12B at `0x41655c`, forced 0 or 1 |
| 3 | `0x415ce7` | outer word0=0; companion=0 | low byte of S+0x2c at `0x41674b`, forced 0 or 1 |

The two word stores at `0x415a50` and `0x41682e` write both adjacent bytes;
the little-endian constants are respectively 0x0001 and 0x0000. They are not
stores of f=1. Error-shaped returns write outer word0=2 and payload at M+8
via `0x416149` or `0x416848`; their trailing flag is not established as active.

Mode 0 calls opaque `0x3c49c0`. NEG/JO at `0x4156fb..0x415701` recognizes
exactly helper word0=T and routes to `0x416ec0` then outer error 2. An optional
input pointer comparison at `0x415797..0x4157a0` can also return outer error:
the qword at optional pointer+0x10 must not exceed the selected helper word.
Other normally returning paths reach the fixed f=0 store. No identity for
that pointer, word or loader policy is inferred.

Mode 1 calls opaque `0x3c5fa0`. Helper dword at S+0x278 equal to 2 selects
outer error. Later the selected returned qword must exceed input qword+0x10
(`0x416091..0x416094`); the original input low EDX byte must be at least 2;
and the formatter's returned word0 must differ from T. Failure routes return
outer error through the displayed diagnostic helpers. Passing routes reach
outer word0=1 and fixed f=0. The concrete numeric comparisons are relevant;
labels such as hardfork, publisher or version are not a reconstructed schema.

Mode 2 calls opaque `0x3c3f00` at `0x415afa`. The zero-minus-word CMP/JNO
at `0x415aff..0x415b09` distinguishes exactly T. Non-T takes `0x416162`,
then `0x416357`; `0x416392` clears R12D. T builds an error-shaped local record
with byte1 at S+0x90. After logging, `0x415cbd` tests that byte's low bit,
calls the opaque object callback at `0x415cd1`, and sets R12B=1 at
`0x415cd3`, bypassing the R12D clear. Both paths reach the same M+0x129 store.
This is a deferred failure-shaped bit: even the T path returns outer word0=0
if the intervening calls return. The callback's contents are not recovered.

Mode 3 reads a selector p from input byte+1 and calls opaque `0x3c5490`.
If p differs from 3, helper word0=T returns outer error 2. Otherwise the
selected helper byte at S+0x280 must equal p (`0x416254`); mismatch returns
outer error, equality sets dword S+0x2c=0 at `0x4162a3`.
If p=3, helper word0=T builds a local failure byte1 at S; a non-T helper
result with byte S+0x1d8 unequal to 3 does likewise via `0x416b00`.
The matching p=3 case clears that local byte at `0x4162e9`.
At `0x41632d`, failure low bit1 invokes an opaque callback, sets AL=1 at
`0x416340`, and stores EAX to S+0x2c. Only its low byte is needed; no claim
is made about EAX's other bytes after the callback. The other path stores
dword zero at `0x416596`. The eventual output copies the low byte only.

These are all ordinary return families. A nonvacuous graph cutset proves
that every structural entry-to-return path crosses one of the four flag
stores or two outer-error stores. Separate cutsets bind the mode-2/mode-3
stores to their defining sites. Register/source analysis remains manual:
the relevant live values are not replaced by another ordinary instruction.
For S+0x2c, the complete explicit first-operand RSP-store census contains
only `0x4162a3`, `0x416342`, `0x416596`. Calls and aliases are not settled by
that census and remain premise 2.

## Caller freshness and byte preservation

Slot `0x7e6560` uniquely binds to metadata `0x415620`. At `0x5e6076` the
output is caller S+0x888. The non-2 test at `0x5e607c` branches to
`0x5e6474`. Subject to the earlier selected RBX=owner+0x70 role, the old
cache is conditionally dropped, then `0x5e648d..0x5e649d` copies 0x150 bytes
from S+0x888 to that cache. The copy import slot `0x7e4b68` is type6,
symbol-index6, `memcpy`; both symbol and RELA bytes are checked.

The corridor returns to `0x5e60af` and checks cached tag !=2 at `0x5e60be`.
It stores that first qword at S+0x170 and copies the other 0x148 bytes from
owner+0x78 to S+0x178. The bit is consequently at S+0x299. The intervening
clone helpers `0x602f70` and their output spills are outside these exported
corridors; their preservation of this live cache copy is an explicit premise.
The final copy at `0x5e6271..0x5e6286` copies 0x150 bytes from S+0x170 to
S+0x370, placing f at S+0x499. Download at `0x5e62d1` receives that record.
Thus the proof connects actual operands while stopping short of a whole
caller reachability or clone-helper contract.

If metadata returns tag2, `0x5e6084` does not replace the cache. It is invalid
to attribute a subsequent download bit to that failed invocation. The cache
may also be tag2 and bypass the selected download entirely. Neither case is
silently promoted to fresh provenance.

Download output is S+0xb0. Only first-word !=T takes `0x5e6320`; otherwise
the caller goes to its failure route and never invokes this publication call.
The qword move from S+0x100 to S+0x160 carries output byte+0x50 to the new
record at S+0x110. Only that qword's low byte is established here; its other
seven bytes may be inactive padding. The other record moves and path-object
move end before the publication call at `0x5e63b6`, which receives that new
record and path S+0xb0. These copies do not prove source-level enum layout.

## Download's two arms and the equality implication

Download first checks `(input qword+0x120 > RCX) OR input byte0` at
`0x4148e7..0x4148fd`. If false, it returns a T-shaped error via `0x4152e4`.
If true, it loads f from input+0x129 at `0x41492d` and saves it at S+0xd.
That is the only explicit RSP store overlapping S+0xd in the complete FDE.
The distinct low EDX input saved at S+0xf does not produce this bit.

Earlier helper/result/cleanup paths can return T-shaped errors before either
arm. No download or publication liveness is claimed. Every route reaching the
ordinary constructed-record store has passed a low-bit test at `0x414c6f`
or `0x415003`:

| f | Selected data-result arm | Constructed D[0x50] | Publication byte gate |
|---:|---|---:|---|
| 0 | explicit 32-byte equality arm | 1 | admits later operation paths |
| 1 | comparison-skipping arm | 0 | rejects before those operations |

On low bit0, the two 16-byte expected blocks copied from input+0x12a are
retained at S+0x200/S+0x210. The call through slot `0x7e5e58` returns a
tagged temporary; byte0=1 routes through `0x4155b0` to T-shaped error.
Otherwise `0x4150a7..0x4150dc` packs its next 32 bytes without changing their
order: overlapping 4-byte loads cover bytes0..6, a qword covers7..14, a vector
covers15..30, and a byte covers31. `0x4150e3..0x415115` compares both halves,
ANDs the equality lanes, and demands PMOVMSKB=0xffff. A lane contributes its
high bit iff both corresponding bytes match, so all 16 bits set is equivalent
to all 32 byte pairs matching. Mismatch calls `0x3f5d10` then writes outer T
at `0x41503d..0x415046`.

On low bit1, the same slot is called into S+0x198. Byte0=1 returns a T-shaped
error. Other results take `0x415146..0x415183` directly to the output join,
without executing the 32-byte comparison. The calls remain opaque; equality
of the two call targets does not establish their I/O or decoding behavior.

At `0x4151c9` the byte is reloaded, XORed with immediate1 at `0x4151ce`,
and stored to D+0x50 at `0x41521b`. This is bitwise XOR, not boolean NOT.
For arbitrary raw input f=3, the low-bit test skips comparison, while XOR1=2
passes publication's nonzero test. Therefore the f in {0,1} producer proof is
essential. The finite algebra checks all 256 bytes and records all such odd
counterexamples; it does not execute captured instructions or assert those
invalid-domain values arise from the qualified producer.

The constructed record's bytes D+0x30..D+0x4f are the same 32 bytes from the
successful data-result arm. At `0x4151df`, the qword stored at D+0x2f includes
the previous field's last byte followed by bytes0..6; subsequent stores at
D+0x37, +0x3f, +0x4f supply bytes7..14,15..30,31. Their surrounding ownership
fields and helper contracts are not reconstructed as source types.

## Publication gate, ordered requests and return stores

Publication stores output O in R15, D in RBX and P in R14. Its first data gate
at `0x416f47` rejects D[0x50]=0. Rejection constructs the bound 36-byte literal
`signature quorum verification failed` at `0x7c08d`, then writes O[0]=1 and
the opaque constructor result at O+8. The graph confirms that the rejection
route reaches the ordinary return without any of the three operation calls
below; cleanup calls still occur and are not claimed side-effect-free.

For a nonzero gate, these are the exact ordered request boundaries:

| Condition/order | Call site and file-bound target | Arguments/result control |
|---|---|---|
| Optional first, if qword D+0x18 !=T | `0x417040`, slot `0x7e5f78 -> 0x3a15d0` | RDI/RSI=qword(D+0x20)/qword(D+0x28); RDX/RCX=formatter's pair; R8=0x7b2640. Nonzero RAX goes through 0x417190 to error1. Zero continues after temporary cleanup. |
| Middle | `0x416fb4`, slot `0x7e5f88 -> 0x3d8d70` | RDI=S, prepared from qword(D+8)/qword(D+0x10) by the opaque formatter. Nonzero RAX goes through 0x417270 to error1; zero continues. |
| Final | `0x417092`, slot `0x7e5f78 -> 0x3a15d0` | RDI/RSI=retained qword(D+8)/qword(D+0x10); RDX/RCX=qword(P+8)/qword(P+0x10); R8=0x7b2658. Nonzero RAX goes through 0x417200 to error1; zero selects success. |

The optional condition is the zero-minus-qword overflow test at
`0x416f51..0x416f57`: signed overflow occurs exactly for qword=T. Formatting,
filesystem naming, permissions, asynchronous interpretation and durability
remain opaque. This packet calls these operation requests, not completed
rename/remove/publication effects.

On final zero, `0x4170f8..0x41710d` copies D+0x30..+0x4f to O+1..+0x20 and
writes O[0]=0. Thus under the composed valid-bit and preservation premises,
these 32 returned bytes equal the earlier input+0x12a expected bytes.
On any displayed failure route only tag1 and O+8 payload are established as
active. Other bytes are not promised initialized source fields.

The common normal cleanup tests qword P+0 and conditionally calls slot
`0x7e4b80` with P+8, that qword, EDX=0. It then calls `0x4201d0` on D and
returns O in RAX. Optional-operation temporaries have their own guarded cleanup
before this join. O remains the displayed result only under preservation
premise2. No physical deallocation or complete ownership conclusion follows.

## What the checks prove

`bindings.json` fixes 46 raw witnesses, the actual four table entries, 18
unique call-slot RELA bindings and the selected copy-import symbol. Full byte
partitions cover the remaining instructions. Eight nonvacuous structural
cutsets and the rejection-path exclusion are recomputed; these are topology
facts rather than symbolic execution. The frame inventory makes pointer
exposures reviewable; it is not a complete alias or transitive write analysis.

Below-identity corruption controls reject witness, table, relocation and FDE
changes. A freshly GNU-decoded mutant jumps over a metadata flag store to the
normal return and is rejected by the structural cutset, independently of the
whole-image hash. A RET-at-entry graph mutant is rejected as vacuous. Finite
predicate checks establish the XOR/domain and equality-mask lemmas only.
Two complete native regenerations must equal the retained tree.

No captured execution, emulator or instruction evaluator is used. Original
source/compiler/ABI identity, crypto policy, old-cache provenance, clone-helper
effects, filesystem behavior, exception ownership and complete lifecycle
reachability remain explicit follow-up obligations. Prior lifecycle bytes are
reused evidence; this packet requests no new recovered-byte credit.
