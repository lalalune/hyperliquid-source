# Pre-Rust: complete adjacent-key last-record compaction

RE-001 / consensus. Node #115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. ELF VA leaf
`0x5b2d510..0x5b2d648`,312 bytes/74 instructions. There are no calls,
indirect transfers, RIP data or external branches. One unreachable4-byte
alignment NOP is context only; the remaining308B/73 starts are selected.
The existing static packet #2525 is credited and preserved.

Argument RDI names an object with backing pointer+8 and u64 length+16.
Premises: valid return stack, disjoint object and nonwrapping writable backing
storage for the old count of32-byte records, no concurrent mutation. The
oracle corpus bounds count to32 and deliberately uses an unaligned buffer.
The capacity word and an original source-level return type are not recovered.
Only memory and stored length are compared, not native RAX scratch state.

Length0/1 returns before reading the backing pointer and without stores.
Otherwise scan adjacent records in order. Equality is exactly the leading
20 bytes, not16 or32: two leading16-byte comparisons are combined with two
MOVD4-byte fragment comparisons; MOVD zeroes its upper12 lanes. PCMPEQB,
PAND and PMOVMSKB produce65535 exactly on key equality. Payload bytes20..31
do not participate. SIMD operations leave integer flags unchanged.

If no equal pair exists, return with every byte and length unchanged. At
the first equal pair (i,i+1), swap both full32-byte rows, keeping the later
record at i. Set write=i+1 and read=i+2. For each remaining read, compare it
with retained row write-1. If equal, swap full read and write-1 rows and do
not advance write. Otherwise copy the complete read row to write and advance
write. Advance read in both cases; store write to the length field at end.

Thus each maximal adjacent equal-key run retains its last complete record;
nonadjacent equal keys remain separate. The backing tail is observable raw
memory and is not erased or discarded in comparison. Distinct-row steps copy
rather than swap. The initial swap, later duplicate swaps and distinct copies
must match exactly over all old-length bytes, including inactive tail rows.

The new safe Rust API will accept mutable32-byte records and return its own
new-length coordinate, without claiming the original ABI/return type. No
allocation, dropping, sorting, original record names or consensus admission
policy is inferred. Key and payload are synthetic opaque bytes, not live
protocol records. Every expected row and byte control is frozen before Rust.

The evaluator needs packet-local MOVD, PCMPEQB, PAND and PMOVMSKB semantics;
shared helpers otherwise cannot evaluate these actual instructions. No shared
tool is changed. Focused ISA tests must cover upper-lane zeroing, byte equality,
bitwise conjunction, mask order, destination zero-extension and preserved
flags. Original ELF/captures/pins remain unchanged; altered bytes use private
COW maps only. No captured ELF process, Unicorn, live service, signing or
chain action is used. New code/docs are independent MIT, no unlicensed source.
All92 gates and byte registrations remain false/unchanged.
