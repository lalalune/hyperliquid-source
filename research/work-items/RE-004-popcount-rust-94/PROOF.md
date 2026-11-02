# Complete population-count and field-adapter relation

The selected node94 body is `[0x5660010,0x5660072)`, 98 bytes and 27
instructions. It has no FDE. The complete FDE parse finds no overlapping
interval, with nearest lower end `0x5660004` and upper start `0x5660080`.
The gap consists of 12 leading INT3 bytes, this body and 14 trailing INT3
bytes. All 25 direct E8 candidates are instruction-aligned calls from six
complete FDE decodes. These facts qualify this entry and extent without
inventing an unwind record or claiming a whole-function census.

The body has one straight-line path, no calls, branches, explicit data-memory
operands or relocated constants, and a single terminal RET. The following
relation covers every raw u64 RDI input; normal code and return-stack behavior
are premises. All arithmetic below is unsigned. The low returned value is
written in EAX, hence the full RAX result is zero-extended.

## Pair lanes do not borrow

Partition input x into 32 two-bit lanes. In one lane, write `2*b1+b0`, where
each b is zero or one. Shifting x right by one and masking with
`0x5555555555555555` leaves b1 at each lane's low position and zeros at its
high position. Subtraction yields `b1+b0`, in 0..2. No lane borrows from the
next, since `2*b1+b0 >= b1`. Thus the first wrapped subtraction equals the
mathematical independent subtraction in every lane and stores the number of
set bits in each input pair.

## Nibble and byte lanes do not carry

Masking the pair counts with `0x3333333333333333` selects one two-bit count
per nibble; shifting right by two and applying the same mask selects the
other. Their sum is 0..4 and fits a four-bit lane. No carry enters another
nibble. Every nibble now contains the count of its original four input bits.

Adding this word to its right shift by four sums each adjacent nibble pair.
Each sum is at most eight, so no nibble addition carries. The final highest
nibble has no incoming shifted neighbor, which also cannot overflow.
Masking with `0x0f0f0f0f0f0f0f0f` keeps only each byte's low nibble. Each byte
therefore contains exactly the count of its original eight bits, in 0..8.
The whole u64 addition is also bounded (highest nibble at most four), so the
Rust checked addition cannot overflow.

## The 32-bit folds preserve the total

Write the eight byte counts as c0..c7 from low to high. The target truncates
to 32 bits when adding the low/high halves. Each retained byte becomes
`c_i+c_(i+4)`, at most 16; no byte carry occurs. Discarding the high 32 bits
loses no contribution to these four retained sums.

The subsequent right-shift-by-16 and u32 addition makes the low two bytes
equal to sums of four original byte counts, each at most 32. Another
right-shift-by-eight and u32 addition makes the low byte the sum of all eight
counts, at most 64. Other byte positions cannot feed a carry into the low
byte. The final `AND EAX,0x7f` preserves exactly this total. A six-bit mask
would incorrectly convert the all-ones input's 64 into zero.

Consequently the returned value is the count of set bits in x, in 0..64, for
every u64 input. The safe Rust retains the target's masks and explicit u32
fold widths. Its wrapping operations make the selected widths explicit;
the lane bounds establish that no unintended cross-lane carries/borrows
change the counted result. Shift counts are fixed below their operand width.

## Complete u32 field caller

The 21-byte FDE `[0x4f9eb90,0x4f9eba5)` consists of ENDBR64, an eight-byte
stack adjustment, a dword load from `[RDI+0x40]` into EDI, the direct call at
`0x4f9eb9b`, the inverse stack adjustment, and RET. The dword load clears
RDI's upper 32 bits, so the helper sees exactly the unsigned u32 field value.
The call's RAX is not changed afterward. Both full-body GNU/LLVM listings
and the call displacement are retained.

Assuming the four object bytes are readable stable ordinary memory, let f be
their little-endian u32 value. This caller returns `popcount64(zero_extend(f))`,
equivalently the count of f's 32 bits. `count_field(u32)` projects that decoded
field into the recovered helper. It does not recreate the pointer, stack ABI,
object layout beyond that read, invalid-pointer faults or concurrency effects.
The expected values for this API are independent counts of the input residue
modulo `2^32`; sign extension is a detectable wrong variant.

## Independent expectations and limits

The oracle counts literal one digits in fixed-width textual binary forms. It
does not use the source's subtraction, masks, lane additions, u32 folds or a
captured-instruction evaluator. Its fixture and source hashes were frozen
before the new Rust existed. It includes all 16-bit words and their 64-bit
complements, all single-byte patterns in each lane and their complements,
all population-count values, field boundaries and digest-derived varied words.

Finite native comparisons exercise independently authored Rust on the host.
The lane proof supplies the full input-domain argument; these checks do not
exhaust all u64 values or prove original compiler/ABI or target-byte identity.
The complete caller set comes from a direct-E8 scan, not a claim about
register-indirect references or all dynamic reachability. Caller purposes,
the reason for missing unwind data and original source provenance are unknown.
