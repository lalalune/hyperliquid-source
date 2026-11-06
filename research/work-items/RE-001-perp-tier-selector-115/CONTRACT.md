# Pre-Rust: node115 tier selection with real split-ring search

RE-001 / assets. Base `05bc2de303c05525b71e7e257426e741bc66a390`.
Node #115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
ELF VAs: caller3c43150..3c432f4 (420B), actual callee4556c50..4556d6b
(283B). Original prefix scope is preserved at Git836753bd8d07e01e7a357f510765f550e7780beb
before closing this dependency. No new Rust exists before the final seal.

Input key is the low32 EDX word. Keys<50 take the global arm before descriptor
selection. A zero loaded guard at64fd8f0 returns four words:1,0,
64fb8f0+32*key,the object+58 retained word. No global row is dereferenced.
Nonzero guard stops BEFORE the actual initializer CALL3c432d9. Its helper,
closure/vtable behavior, post-initializer continuation, concurrency and original
global contents remain unknown. Synthetic guard is a snapshot premise.

For key>=50, only descriptor qword8000000000000000 selects the inline tree.
Object+38 is the node root and+40 its remaining height. Null root stops at
the actual diagnostic call. Node count is u16 at+2f6, sorted u32 keys at+2c8,
64-byte rows start at+0, children pointers at+2f8. Scan while query>key using
unsigned32 comparisons. Equality selects that row; a smaller query descends
through the corresponding child slot. Exhausting keys chooses child[count].
A required descent at height0 stops before diagnostic3c432ee; otherwise
decrement height and load the selected child. Match outputs are row+8,
row+16,row-address+24,row+56. Original names, values/units and ABI are unknown.

Other descriptors use a valid bounded sorted ring: capacity C at object+30,
buffer P at+38, head H at+40, count N at+48. Premises C<=16, N<=C,
H<C (or H=N=0 for C=0), nonwrapping valid disjoint storage, strictly increasing
logical u32 keys. Physical rows are72B with key at+0. Inactive capacity is
left unknown in the evaluator; it must not be read. The real CALL at3c4322c
enters4556c50, pushes its actual continuation and RETs into3c43231.

The callee is integer-only and has no calls. It computes the two contiguous
spans of the ring. With wrapping, the first key of the second span chooses
which span to search; equality there returns the first span's logical length.
Both span searches use unsigned comparisons and return an active low status
bit and logical position on a hit. No helper return is supplied. The caller
tests AL bit0 and bounds the returned position by N before adding H and
subtracting C once when needed. A hit selects P+72*physical+8, then returns
fields at physical row+16,+24,pointer+32,+64. Miss stops before the actual
diagnostic CALL; no diagnostic return or unwind behavior is assigned.

Compare all three scalar returned words and exact pointer identity, normalized
bijectively to global cell/index/byte-offset, tree node/slot/byte-offset, or ring
physical-row/byte-offset. Correct offsets are global0/tree24/ring32. Pointer
changes are not masked away. Initializer I and diagnostic M are owned analysis
frontiers, not returned enums. Every real returned result checks RAX/output
identity, outer RET and restored RSP. Incoming object/guard/nodes/ring remain
unchanged. Unknown padding and uninitialized unused capacity stay unknown.

Finite tree premise: at most16 nodes,11 keys per node, height<=3, distinct
ascending keys, matching row counts and valid acyclic child shape. Row fields
are raw u64 operands, not original enum/metadata validity or caller reachability.
The source API may refuse out-of-domain input separately; that is its own
policy, not native rejection behavior. Original full container types and all
network/business validity remain unclaimed. All92 acceptance gates stay false.

The complete two-FDE export is703B/197 instructions. The selected closed
ordinary-return/pre-call graph visits682B/192 starts: exclude one unreachable
alignment NOP, initializer CALL/postcall bytes and diagnostic CALL bytes.
Instruction visitation is not exhaustive branch-state proof. In particular,
the post-helper index-failure edge cannot be reached by a correct search hit
under these bounded valid ring premises, though the guard instructions and
diagnostic destination are checked. Compiled-byte identity is not claimed.
