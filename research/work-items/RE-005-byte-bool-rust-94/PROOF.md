# Independent one-byte decoder state and write relation

This proof binds node #94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete u8 leaf is ELF VA `0x466bbb0..0x466bc09`, 89 bytes / 28
instruction rows. The complete boolean leaf is `0x466be00..0x466be6c`,
108 bytes / 36 rows. Ends are exclusive. Their 197 bytes / 64 rows have
complete contiguous GNU byte partitions and independently read FDE/CIE bounds
in `NATIVE-INTAKE.json`. Neither body calls another function, reads RIP-relative
data, dispatches a table, or has an opaque helper. Source-level labels are
inferences from the complete transfers; no original Rust type or ABI follows.

## Ordinary separated-memory domain

Let O be the entry output pointer and D the entry state pointer. The observed
state fields are DWORD m at D+0, QWORD L at D+8, pointer P at D+16, remaining
length n at D+24, and QWORD C at D+32. The input is a valid immutable readable
slice, with nonwrapping cursor arithmetic. Input, output, state, code and live
frames are separated and remain unchanged except for the writes below. Calls
return ordinarily; faults, unwind, concurrent mutation and aliases are excluded.

The projection records the raw tag written to O+0, optional byte write to O+1,
optional QWORD write to O+8, counter store, consumed count and complete suffix.
Absent writes are represented by null; this is not a read of inactive native
result bytes. The chosen safe interface does not reproduce native result
padding, physical pointers, hidden registers or the original enum layout.

## Fixed one-byte budget before input access

Both bodies compare the complete DWORD m with exactly 1. When m differs from
1, C and L do not participate in the selected path and no counter store occurs.
Otherwise, let M=2^64-1. The exact QWORD comparison checks C==M before loading
L, adding, storing or touching the input cursor. Equality returns raw tag 2,
leaving the counter and cursor unchanged.

For C<M, C'=C+1 is an exact nonoverflowing unsigned sum. Both bodies store C'
to D+32 before testing unsigned old C>=L. For C<M, C>=L is equivalent to C'>L:
integer values have no point strictly between C and C+1. Failure returns tag 2
with the increment retained and the cursor unchanged. Otherwise decoding
continues with C'. Equality C'=L is admitted, including C=M-1 and L=M. The
order means that budget failure precedes an empty-input shortage, and repeated
nonoverflow limit failures keep charging until C reaches M. Other mode DWORDs
skip the complete gate, regardless of their low bit or nonzero value.

The two tag-2 paths have a real output-write difference: the u8 leaf writes
only O+0. The boolean leaf sets CL=2 before its overflow test, then enters a
shared epilogue that writes O+0 and QWORD O+8=1. This auxiliary write also
occurs on boolean budget failure and must remain observable in this projection.
It is not a claim that a recovered budget-error source enum owns a need field.

## Empty and nonempty inputs

After budget admission/bypass, n=0 returns tag 0 and QWORD O+8=1. No cursor
store occurs. A successful budget charge remains stored on this shortage.

For n>0, each leaf loads the unsigned first byte b, stores P+1 to D+16 and
n-1 to D+24, and only then classifies or returns b. No suffix byte is read or
changed. Thus the consumed count is exactly 1 and the full residual input is
the original slice without its first byte, for success and invalid boolean.

The u8 leaf writes b to O+1 and raw tag 18 to O+0 for every b in 0..255.
It has no invalid-byte branch. The boolean leaf instead partitions all 256
bytes: b=0 writes the little-endian word 0x0012 to O+0, b=1 writes 0x0112,
and b=2..255 writes tag 8 to O+0 and the original byte b to O+1. It does not
normalize arbitrary nonzero bytes to true, and its rejection consumes b.
All nonempty outcomes write O+1 and do not write O+8.

Each leaf initially copies O to RAX and leaves that return pointer intact.
No stack storage or callee-save register is modified. The complete bodies'
conditional branches are exhausted by: m==1 versus other DWORDs; C==M versus
C<M; old C>=L versus C<L; n==0 versus n>0; and, for boolean, b==0, b==1 or
b>=2. Every ordinary return therefore belongs to the relation above.

## Independent mathematical authority and implementation boundary

`freeze.py` uses only integer inequalities, byte indexing, and ordinary slice
suffixes. It has no PC, register, opcode or instruction interpreter and imports
no repository module. All 256 bytes, mode equality controls, unsigned counter
endpoints, limit equality/one-below/one-above, empty inputs, invalid booleans and
unchanged suffixes are corroborated by independently generated finite cases.
The partition proof supplies the unbounded mode/limit/tail argument; finite
cases are not captured execution or exhaustive testing of every native state.

The proposed standalone safe Rust component receives a borrowed slice and a
chosen Budget record. Result variants may retain the boolean tag-2 auxiliary
write explicitly. A separately linked client receives only input TSV rows;
the comparator owns the frozen expected JSONL. No implementation is read before
the authority freeze. Original ABI/type ownership, machine-byte identity,
whole serialization, target execution and full component gates remain open.

Live ownership intake found no PR matching either exact address, and the
existing `stream-msg-codecs-94` packet explicitly excludes the u8 body.
PR #1365 owns the distinct u32/u64 472-byte wrappers and their caller;
this pair does not modify that crate or repeat its implementation.
