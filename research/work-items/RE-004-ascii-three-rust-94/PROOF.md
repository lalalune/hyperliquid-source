# Three-byte ASCII equality, including the complete RAX result

This proof binds all 143 bytes of node94 ELF VA `[0x151a4a0,0x151a52f)`
to the target digest in `static.json`. GNU/LLVM/Capstone agree on its 47
instruction boundaries. It has three conditional branches, two returns,
no calls, no writable fields and no static lookup table.

## Length gate and byte fold

The initial `cmp rsi,3` has a 64-bit operand. Its JNE goes directly to
`xor eax,eax; ret`, without reading either input pointer. Thus every u64
length other than exactly three returns zero. In particular 259 and
`2^32+3` are rejected; truncating the length to a byte or dword is incorrect.

For length three, each source byte b is loaded with MOVZX into EAX. LEA
computes b−65 in a 32-bit register, but CMP reads only its low byte. Its
unsigned comparison is therefore `(b−65) mod256 < 26`.

- If b<65, the difference is in 191..255 and the test is false.
- If 65<=b<=90, the difference is in 0..25 and the test is true.
- If b>90, the difference is in 26..190 and the test is false.

SETB produces a byte 0 or 1, SHL5 makes 0 or 32, and OR with b returns
`b|32` exactly in the uppercase ASCII interval. Every byte in 65..90 has
bit5 clear, so OR32 equals addition of 32 there, without u8 overflow. The
Rust fold uses that inclusive range and addition; all other bytes remain
unchanged. Punctuation, NUL and non-ASCII bytes are not normalized.

Each side is folded independently. The first folded pair at offset 0 is
compared and a mismatch returns zero immediately. The same holds for the
pair at offset 1. Only after both pairs match is offset 2 read and compared.
The selected value is one exactly when all three pairs agree. There are no
dynamic lengths, terminator reads or reads beyond offset 2.

## Full register result, not just AL

The final successful-path return writes AL with SETE. This alone would not
establish the high bits of RAX. Here the immediately preceding read of
the right offset 2 byte at `0x151a514` is MOVZX EAX,byte[rdx+2], which
establishes bits8..63 of RAX as zero. Subsequent instructions modify EDX,
DL and flags, leaving those RAX bits unchanged. SETE replaces all eight
low bits with 0 or 1. Therefore the complete RAX is 0 or 1 on this path.
Earlier failures execute XOR EAX,EAX, likewise clearing the complete RAX.
Converting the Rust bool to u8 in the driver preserves this full numeric
return; it is not a mask hiding unconstrained native return bits.

## Safe value domain and memory observations

The API accepts a raw u64 length and two fixed three-byte snapshots.
All bit patterns are admitted, and all indexing uses the constant positions
0, 1, 2. The loop exits on the first mismatch and has at most three iterations.
The length gate precedes any byte indexing. Rust array references are valid
by construction; this API does not reconstruct native pointer validation.

For the original memory correspondence, every byte actually read must be
valid stable ordinary memory. The slice snapshots strengthen availability
to all three bytes even for an early exit. The original may return normally
after an early mismatch with later bytes inaccessible; such fault-observation
behavior is outside the value projection. Input aliases are harmless under
stability because there are no stores; consistent snapshots represent the
same bytes. Concurrent changes, volatile/MMIO reads, timing, faults, flags,
scratch registers, pointer ABI and source identity are unclaimed.

## Independent equivalence-class oracle

The frozen oracle defines 26 disjoint two-element sets using the literal
uppercase and lowercase ASCII alphabets, then 204 singleton sets for all
remaining bytes. It checks that these classes form a partition of all 256
byte values. Two bytes are equivalent when their class identifiers agree.
This construction uses neither the decoded wrapped subtract/compare nor
Rust's range-plus-add fold.

For a letter pair, both uppercase and lowercase fold to that pair's lowercase
member. A singleton nonletter folds to itself and cannot equal a letter's
lowercase output. Hence class equality is equivalent to equality of the
two target folds for every possible ordered byte pair. Taking the conjunction
for three positions and requiring the full length to equal 3 derives the
complete oracle relation independently.

The corpus includes every one of 65,536 ordered byte pairs at each position,
with the other positions equal under the classes. Those 3 exhaustive pair
sweeps share one common baseline record, so deduplication removes two copies. It also
includes length boundaries, mixed byte arrays and 4,096 deterministic varied
arrays with self-equality counterparts: 204,864 distinct cases overall.
It does not enumerate all 256^6 full-array pairs or all 2^64 lengths; the
separable proof above provides that generality. Native comparisons and
mutants corroborate the implementation and compiler path.

## Static caller and reference scope

The full caller FDE `[0x151b100,0x151b6a3)` contains 1,443 bytes and 408
instructions. The complete .text E8-candidate scan finds sites `0x151b4f9`
and `0x151b527`, both confirmed at decoded instruction boundaries calling
this leaf. No caller purpose or source string identity is inferred.

The complete 121,299-FDE inventory binds unique exact leaf/caller extents,
and retained raw records bind their CIEs. Fourteen preceding INT3 bytes and
one following INT3 byte are outside the leaf. All 80,300 RELA entries are
scanned: none names the entry or writes over protected body/padding/caller
bytes. These facts are not a complete indirect-call/reference census. The
leaf's data consists entirely of supplied input bytes; no data table, helper
or runtime global needs to be guessed to close this value relation.
