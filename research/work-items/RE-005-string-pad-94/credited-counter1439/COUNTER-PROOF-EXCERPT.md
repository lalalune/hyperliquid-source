# Credited character-counter theorem from reviewed PR1439

Original source commit24167e3a452d8eda4857918245f022da487620c9.
Original full proof SHA256 eb0eefb396a17513ec7fa6c48ce8db94e7fc97124e9adc25fd46e50a5fff4202.
The counter section is retained for dependency closure with terminal blank lines omitted; no new helper recovery is counted.


Let q(b)=1 when b<128 or b>=192, otherwise0. Signed-byte comparison against
-64 at scalar sites is exactly this predicate. The bound constants BF/BF plus
the two QWORD ones make the observed two-byte SIMD expansion/reduction sum the
same predicate for each loaded byte. Its repeated groups load two WORDs per
four bytes and preserve a count in QWORD lanes, followed by at most3 scalar
bytes. Main's prefix<32 path processes floor(n/4)*4 bytes this way and the
remaining0..3 bytes; all fixed loads are inside the declared slice.

The >=32-byte count helper has no CALL or external helper. For any aligned
u64 word x, define K(x)=((~x >>7)|(x>>6)) &0x0101010101010101, with the
complement interpreted modulo2^64. The bit at8j is (!bit7(b_j))|bit6(b_j),
which equals q(b_j); all other bits are0. Shifts crossing byte boundaries cannot
affect those selected bit positions. Thus K packs eight independent0/1 bytes.

For starting address p, a=(-p) mod8 is0..7. If n<a or n-a<8, the helper uses
the four-byte/scalar whole-slice count just described. Otherwise it partitions
the slice into prefix[0,a), q=floor((n-a)/8) aligned words, and tail of
t=(n-a) mod8 bytes. Prefix and tail use the same byte predicate; no partition
overlaps or omits a byte. The scalar tail mask clears no real length bit under
n<=isize::MAX. The pointer alignment can vary across all eight residues.

Aligned words are processed in batches k=min(q_remaining,192). The native
32-byte vector grouping handles four words; its128-byte unrolling is simply
four such groups. The unpacking only rearranges QWORD lanes before the same
K expression and QWORD addition. After grouping, each packed byte accumulator
is in0..k<=192<256, so additions cause no carry between neighboring byte lanes.
Any residual1..3 words are handled by the same scalar K formula. A nonzero
residual can only occur in the final batch because192 is divisible by4.

For packed accumulated bytes c0..c7 with0<=ci<=192, the mask
0x00ff00ff00ff00ff and shifted masked value form four16-bit limbs
u0=c0+c1,...,u3=c6+c7, each<=384. Multiplication modulo2^64 by
0x0001000100010001 has top16-bit limb u0+u1+u2+u3<=1536<65536.
No lower triangular limb sum can carry, since each is bounded by1536. The
observed right shift48 therefore returns exactly the sum of all byte counts.
Prefix/tail plus all disjoint batches prove count=sum q(P[i]) for every valid
slice length/alignment, including invalid UTF8 byte patterns as a byte relation.
For valid UTF8, exactly one non-continuation byte starts each scalar, so this
also equals the Unicode scalar count. No PC/register/opcode execution is used.
