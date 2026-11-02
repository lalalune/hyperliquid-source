# Indexed accumulator: complete memory and RAX relation

This is a normal-return correspondence for the 44-byte node #94 leaf
`[0x514ac60, 0x514ac8c)`. Its target SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The proof covers every admitted image byte value, every signed 32-bit index,
all u64 addends/base values and supported aliases. Successful target execution
requires ordinary mapped readable/writable memory, unchanged code and normal
stack/control behavior. Faults, races, externally observed intermediate stores,
MMIO and output aliases with code/control state are excluded.

## Static closure and the corrected return value

Fresh GNU/LLVM exports and Capstone agree on all 12 instructions and their
boundaries. `verify_static.py` binds the complete body hash
`4aec06b08170d83e53cc0c7ffd81f0f74635ccdffa3ac1f23e993186096ccae9`, exact CIE/FDE
records and both neighboring FDEs. The preceding body `[0x514ac40,0x514ac5f)`
has one trailing INT3; four INT3 bytes follow the selected leaf, before the next
body `[0x514ac90,0x514ac95)`. The only branch, JE at `0x514ac72`, targets the
base load at `0x514ac78`. One RET ends the body; there are no helper calls,
external constant reads or LSDA.

All 80,300 RELA records are checked for an addend naming the entry and for
eight-byte writes overlapping the protected code/padding. Neither is found;
the encountered relocation kinds are 1, 6, 7, 8 and 18. Whole-text byte scans
find no E8-relative call or E9-relative jump candidate to the entry. Thus no
incoming caller is claimed or invented. This bounded encoding/relocation census
does not exclude register-indirect references, other encodings or other data
paths, and does not identify the source function or imply that it is unused.

The previous `foundation-indexed-accumulator-94` README and tool header say that
the index remains in RAX at return. The complete bytes contradict that sentence:
`48 8d 04 c2` at `0x514ac7b` is `lea (%rdx,%rax,8),%rax`. RAX then holds the
loaded base plus eight times the index. Both subsequent ADDs have memory
destinations and leave RAX unchanged. The returned full register is therefore
the entry address, not the index. This packet preserves the earlier files and
tests as historical evidence; their success is not evidence for that old return
claim. The new oracle and compiled `return_index` control address it directly.

## Integer and load order

Let `M=2^64` and let each memory operand denote a little-endian unsigned value.
Arguments are the three addresses originally in R8, RCX and RDI, here called
`P`, `A` and `B`. In instruction order:

1. Load qword `p = memory[P]`, then qword `a = memory[A]` unconditionally.
2. If `p=0`, use integer index `i=13`. Otherwise load the dword at
   `(p+32) mod M` and interpret it as signed i32, so `-2^31 <= i < 2^31`.
3. Load qword `b = memory[B]`. Calculate `e=(b+8*i) mod M` in RAX.
4. Add one modulo M to the qword at `c=(e+176) mod M`.
5. Add the already loaded `a` modulo M to the qword at `s=(e+64) mod M`.
6. Return `e` in full RAX.

MOV EAX,13 zero-extends on the default path. MOVSXD sign-extends all 32 index
bits on the other path. For negative `i`, casting through signed i64 to u64
produces `i mod M`; multiplying that residue by eight and adding `b` modulo M
gives exactly the LEA result. Memory operand displacement additions also wrap
modulo M before mapping the accessed bytes. No returned-address validity check
exists in the original: it does not dereference `e` itself.

The counter and sum each use a full eight-byte ADD. Their results depend on no
incoming flags, and neither subsequent control flow nor RAX consumes the flags
they produce. This component claims their memory values and RAX, not flags.

## Aliases and the independent final-byte formula

All pointer/index/base/addend inputs are read before either store. Consequently
those values are snapshots even when their read ranges overlap the updated
words. The addend is read even on the default-index path. Reloading it after the
counter update can change the answer and is not permitted by the instruction
order.

The two output starting addresses satisfy `c-s = 112 (mod M)`. Each admitted
eight-byte access is nonwrapping. If their intervals overlapped, the difference
between their start addresses would have magnitude at most seven, incompatible
with either representative `112` or `112-M`. Thus the two output words are
disjoint for every admitted layout, including when calculating either address
wrapped. The second ADD reads its own original word despite occurring after the
first ADD. No input alias changes this fact.

Let `C0` and `S0` be the original counter and sum words, and define
`C1=(C0+1) mod M`, `S1=(S0+a) mod M`. The final byte at address `x` is byte
`x-c` of `C1` when `x` lies in the counter interval, byte `x-s` of `S1` when it
lies in the sum interval, and the original byte otherwise. Because the intervals
are disjoint, this immutable overlay is unambiguous. It characterizes all byte
values and all permitted aliases without enumerating them or simulating x86.

## Safe image admission and Rust refinement

Image byte `j` represents unsigned address `image_base+j`. A nonempty image is
admitted only if its last byte address fits u64; ending exactly at `u64::MAX`
is allowed. For each actual access, `span` requires checked subtraction of the
image base, checked conversion to usize, checked endpoint addition and inclusion
within the slice. The complete image is nonwrapping, so an admitted span cannot
cross the u64 address boundary. Effective address calculations before this check
retain their native wrapping semantics; they are not confused with checked
memory-span arithmetic.

For example, `p=2^64-32` reads its index field at address zero. Likewise a returned
entry `e=2^64-1` accesses sum bytes starting at 63 and counter bytes starting at
175. These arithmetic cases are supported when those actual bytes are mapped by
the supplied image. The symbolic image alone does not establish that a target
process could access arbitrary numeric addresses; target correspondence is
conditional on its ordinary valid mapping and normal execution.

The implementation follows the observed input read order. It checks both output
spans before writing, then performs the counter update and sum update in order.
All reads and copies use spans of exactly four or eight bytes, so conversion to
fixed-size arrays cannot fail. Every slice index is bounded and every value
arithmetic operation that could overflow is explicit wrapping arithmetic. There
is no loop or dependency on arbitrary traversal/size caps. A single `&mut [u8]`
permits internal aliases without creating aliased mutable Rust references.

The seven `AccessError` variants are new safe admission outcomes. Every error
leaves the complete image unchanged; notably a missing sum span is rejected
before incrementing a valid counter. The original could fault on the later ADD
after the earlier write. This intentional atomic refusal is additional API
policy and does not reconstruct original fault behavior. On successful admitted
normal-return paths, the integer and overlay relations above establish the same
memory and full numeric RAX result.

## Frozen expectations and evidence limits

`oracle.py` uses unbounded signed integer arithmetic, then reductions modulo M,
and the immutable final-byte formula above. It does not call Rust, execute
captured instructions, decode instructions or emulate register state. Its source,
the static evidence, target identity and input/expected streams were hash-bound
while the Rust source directory was absent. The guard and hashes record local
chronology; they are not an external timestamp attestation or an independent
execution of the original.

The 3,120 frozen descriptors contain complete initial images; the native client
only reads those inputs, calls the new library and emits the complete backing
image plus the value/error result. Native finite coverage supports the Rust
implementation; this proof establishes the full admitted byte/arithmetic domain.
It does not establish original ABI, compiler provenance, target compiled-byte
identity, caller purpose, application meaning or whole-node equivalence.
