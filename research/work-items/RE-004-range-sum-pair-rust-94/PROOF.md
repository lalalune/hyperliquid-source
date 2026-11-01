# Range-sum pair and its mandatory shared read

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The selected complete FDEs are `[0x514bc60,0x514bcc3)` (99 bytes),
`[0x514bcd0,0x514bd38)` (104 bytes), and their entire shared helper
`[0x5032f40,0x5032f4d)` (13 bytes). Total: 216 bytes / 65 instructions.
The two loops are one related family. Historical static packets #1346/#1349
provide context, but neither reconstructs their memory behavior in Rust.

## Closed instruction relation

Write `q(a)` for the little-endian qword read at numeric address `a`.
Effective-address additions and cursor arithmetic are modulo `N=2^64`.
Both outer functions first read

`P=q(O+0x788), Q=q(P+0x30), B=q(Q+0xb18), E=q(Q+0xb20)`.

The two bounds are mandatory even when B=E. Let `C_i=(B+16*i) mod N`.
When the initial comparison is equal, there is no entry/helper read. Otherwise
each iteration reads `S_i=q(C_i)`, increments its cursor by 16, reads
`A_i=q(S_i)`, and calls the included helper with RDI=A_i. The helper reads
`H_i=q(A_i+16)` and returns `(H_i+62) mod N` in full RAX. It changes no other
general register and performs no data writes or further calls.

The first loop adds that returned value to its running 64-bit sum. The second
loop reloads `q(C_i)` into RAX, discarding the helper result, and instead adds
`q(S_i+80)`. The reload has the same value in stable memory because neither
loop nor the helper writes data before the final output. The helper read still
must succeed in the second loop; absence of its contribution is not permission
to omit its input accessibility. The two accumulation relations are

`T0 = (sum_i H_i + 62*n) mod N`

`T1 = sum_i q(S_i+80) mod N`.

After its last comparison, each function stores exactly eight little-endian
bytes of T at D, sets full RAX=1, restores RBX/RBP/R12/R13 from its stack,
and returns. All data reads occur before the output store. Thus output aliases
with any chain, bounds, entry or target bytes are supported without changing
the computed sum. Bytes outside D..D+7 remain unchanged. RSI is D throughout;
RDX and RCX are never written; R8..R11/R14/R15 are untouched. RDI is O for an
empty range, or the last helper argument A_(n-1) for a nonempty range. It is
not the slot pointer, cursor, helper return, or original object in that case.
The API returns full RAX/RDX/RDI/RSI, and documents preservation of the other
general registers. RSP/RIP, flags and stack bytes are outside its projection.

## Termination and finite safe images

Adding 16 modulo N has period N/16. If `(E-B) mod N` is not divisible by 16,
the original equality test cannot terminate under stable memory; it either
faults or continues indefinitely. The safe API refuses this case. Otherwise,
the first equality occurs after `n=((E-B) mod N)/16`, in `[0,N/16)`.
This includes zero iterations and a wrapped final cursor. Requiring E>=B,
requiring the terminal cursor to be mapped, or treating E as a signed bound
would incorrectly exclude valid finite executions.

The image represents `[base,base+len)` with mathematical endpoint at most N.
Each accessed qword must fit all eight ordinary bytes in that single interval.
The API accepts arbitrary u64 numeric fields, unaligned addresses, zero roots,
independently wrapping field formation and stable read-role aliases. A qword
may end at N, but a qword's bytes may not wrap beyond the image. Numeric
addresses never become host pointers. The input client's fixed capacity is
only a fixture framing choice, not an implementation limit.

Before traversing, the implementation may reject `n>len/8`. This is a proved
impossibility check, not an iteration budget: the n distinct cursor positions
are separated by 16 around the address circle, so their eight-byte entry
reads are pairwise disjoint. A successful traversal therefore needs at least
8n mapped bytes. If a qword crosses N, it is already outside this image domain.
The shortcut cannot reject any admitted successful traversal. For all other
cases there are exactly n iterations; each reads the actual wrapped cursor
and pointer fields. No artificial maximum length/count is imposed.

Every validation and reached-field read completes before the only mutation.
An absent chain field, entry, mandatory helper field, selected contribution,
output span, invalid image interval or unreachable endpoint returns None with
the entire image unchanged. None is a new safe refusal, not an original return,
fault order or simulation of nontermination. Valid empty ranges require only
their chain/bounds/output, not their numerical endpoint or unused data fields.
Entry second qwords are never required; the last entry needs only its first
eight bytes. The cursor after the last entry is not dereferenced.

Original correspondence assumes stable ordinary memory, valid normal control
flow, and original stack/call-return storage disjoint from the entire image.
MMIO, concurrent mutation, invalid-access ordering and stack/data aliases are
excluded. These assumptions justify using immutable entry reads, computing the
sum before storing, and omitting redundant duplicate reads. They do not permit
skipping a reached field merely because its loaded value is discarded.

## Rust arithmetic and composition

Checked subtraction converts an admitted numeric address to a slice offset;
checked offset+8 and the global u128 endpoint comparison prove all slices safe.
Wrapping additions form fields and cursors; wrapping subtraction computes the
modular distance. The low four distance bits decide divisibility before the
count is obtained. The count bound is proved above. Each helper sum and running
sum uses wrapping u64 addition, which equals the whole unbounded sum modulo N.
Induction on the iteration number proves both the cursor and running sum.
The last argument variable starts at O and changes only after the actual
double dereference, yielding the exact empty/nonempty RDI relation.

The helper's successful read is expressed before the member-dependent choice.
Even when the selected member ignores its value, failed lookup propagates None.
This recovers the missing memory premise in a model that would otherwise take
only a list of already-dereferenced numeric contributions.

## Independent evidence and limits

GNU, LLVM and Capstone bind every selected instruction and its complete FDE/CIE.
The only two outgoing calls are to the included helper. Their branch targets
are internal to their own bodies. The complete .text E8/E9 scan yields ten
candidate helper calls, two selected and eight sites in seven complete external
caller FDEs; all are checked at actual decoded call boundaries. Neither outer
entry has a direct candidate. All RELAs are checked for entry naming and code
writers. This does not establish all indirect callers or recover the external
callers' surrounding algorithms. No static table/import dependency remains.

The pre-Rust oracle resolves an immutable address dictionary, materializes all
entry pointers and helper arguments, then uses one whole sum and immutable
output overlay. It uses modulo/division instead of the Rust wrapping loop.
The count impossibility bound follows distinct mandatory bytes, independently
of either implementation's loop structure. Frozen inputs include empty unmapped
endpoints, first-qword-only entries, wrapped terminal cursors, absent discarded
helper reads, output/read aliases, global image overflow and arbitrary values.
Finite native comparisons qualify new host Rust; the general relation is proved
above. No captured execution, instruction emulator, original compiled-byte or
whole-node equivalence, native ABI recovery or component gate completion is
claimed. Imported material and reference pins remain unchanged.
