# Proposed complete padding request relation, before new Rust

Target node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Main VA15723b0..15728bf:1295B/341 rows, body8999b0718558a75e048359c74e547192461d16e0b843c97cba6951d31d556aed.
Prefix helper1572350..15723a4:84B/37 rows, bodyb2b1ff7af9c92df0857e5a876f7303e4d7ece768781101580da0d3389efa7382.
Count helper15796c0..1579c8b:1483B/365 rows, body13c5b0904bd66520b303cc5513d2cf7fed55c20298a5bef6a979f81be0083f35.
The main and count bodies match their actual official libcore function sections
outside seven and five actual four-byte ELF relocation fields respectively.
The admitted archive/member are ca804049...ab256 /57ca5807...32d13. This is
published-artifact correspondence, not newly rebuilt original Rust provenance.

## Domain and chosen observations

Normal, readable, nonwrapping byte slices P (prefix) and D (digit buffer), valid
formatter header, writer context and immutable callback code/input regions.
The slices and live frame are separated from inappropriate raw aliases.
Callbacks return normally with ordinary preservation. They may sequentially
mutate the chosen live header/data/table/method cells, while input/code/frame
storage remains immutable and all selected table IDs remain valid.
Faults, unwind, invalid pointers, concurrent mutation and original types/ABI are
outside this relation. Target x86-64 slice lengths are <=isize::MAX, so
len(P)+len(D)+1 <=2^64-1 and content-count arithmetic does not overflow.

Choose live header word W=QWORD(F+16), full u32 S corresponding to ESI,
a valid UTF8 prefix slice, a raw digit byte slice, one borrowed writer state,
logical table/method IDs in live Cells and a supplied opaque FnMut sink.
Observe individual Char(raw_u32) and Str(raw_bytes) requests, current header
word at each request, final W and normal lowAL. Snapshot metadata is chosen;
native calls receive writer context/arguments. No actual Unicode encoding,
writer implementation, native pointer identity or hidden register is asserted.
Main captures original writer data D0 and table T0 before the first callback.
Every subsequent dispatch uses D0/T0 even if callbacks change the live header's
data/table fields. The actual char/str method slot in table T0 is reloaded on
every dispatch, so mutations of that table's slots affect subsequent calls.
All these live Cells persist after the invocation, except for the explicit
zero-path header restoration described below.

## Prefix-count closure for arbitrary byte values

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

## Signs, optional prefix and width

Let W0 be the initial word. flags=low32(W0); width=(W0>>32)&65535;
precision=(W0>>48)&65535 is not used for layout. All layout/sign/fill values
are determined before callbacks and do not follow later header mutations.
If full S==0, request sign '-' (45) and count1. Otherwise sign is '+' (43)
and count1 when flags bit21 is set, or sentinel0x110000 and count0.
Bit22 does not change the sign choice. S=256 is nonnegative, not false.

If bit23 is clear, the native prefix pointer becomes0 and its count is0,
regardless of the original P length. Otherwise keep the original nonzero safe
prefix pointer and add sum q(P[i]). In particular enabled P with length0 is
present, not absent. Content length L=len(D)+sign_count+prefix_count; digit
buffer length counts raw bytes, not its Unicode scalars.

The84-byte prefix helper receives cached D0/T0 and first requests Char(sign)
unless sign is sentinel, loading T0's current char method slot.
Any nonzero sign callback status causes helper lowAL1. It then tail-dispatches
Str(P) when the effective pointer is nonzero, even for an empty enabled P,
forwarding that prefix callback's raw status. That dispatch reloads T0's str
method after any sign callback mutations. Otherwise it returns0. The main
caller tests any nonzero helper result and normalizes its own result to1.

If L>=width, there is no padding or header mutation even with bit24 set.
Call the prefix helper; on its error return1. Otherwise tail-dispatch Str(D),
including empty D, reloading T0's str method after the prefix helper. Return
that final callback's raw lowAL unchanged. This
is the one main path where a nonzero digit status need not normalize to1.

## Ordinary padding and complete error order

When L<width, let A=width-L in1..65535. If bit24 is clear, alignment code
(flags>>29)&3 selects preceding fill counts [0,A,floor(A/2),A] for codes
[0,1,2,3]. Trailing count is A-preceding. Fill is raw flags&0x1fffff,
without assuming the extracted u32 is a valid Unicode scalar.

Request Char(fill) preceding times, then the sign/prefix helper, then Str(D),
then Char(fill) trailing times. Stop immediately after the first nonzero raw
callback result and return1. On all successes return0. The helper does not
write W here; final W and other live Cells retain callback mutations.

The trailing-loop normalization follows the actual16-bit counter, not an
assumed Rust Result type: after j>=1 attempted trailing callbacks it has low16
j-1, and j<=trailing<=65535. The final unsigned comparison against trailing is
therefore true on every failure. If all trailing callbacks succeed, the loop
sets the counter equal to trailing before that comparison, yielding0.
This includes an error at the final trailing callback and trailing65535.

## Zero padding, visible mutation and restoration

When L<width and bit24 is set, save the original full W and replace only its
low DWORD with (flags&0x9fe00000)|0x20000030. The high32 (width/precision)
remain unchanged; the fill becomes raw'0' and alignment bits become right1.
Request the sign/prefix helper, then A individual Char(48), then Str(D).
Every nonzero callback at any of these stages returns1 immediately and leaves
the CURRENT W, including any preceding or failing callback mutations. Only
after final digits success restore the entire initial W0, overwriting even
callback changes to width/precision, and return0. Writer data/table/method Cells
are not restored. There is no trailing padding on this path.
No callback is retried and there is no output rollback.

## Status and remaining limits

This gives the complete normal callback/header/lowAL relation for all branches
of the1295-byte main plus both real fixed helpers under the stated domain.
Every callback receives the same writer state. It does not implement the
opaque writer's output/Unicode/errors, original private ABI/types/compiler,
unwind/alias/fault cases or full node. No component gate is requested. A fresh
independent oracle must be frozen and reviewed before new Rust is authored.
