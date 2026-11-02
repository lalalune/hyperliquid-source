# Independent integral-padding normal-proxy relation

The target is node94,91774280 bytes,SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
The primary complete FDE is ELF VA15723b0..15728bf,1295 bytes/341 GNU rows,
body8999b0718558a75e048359c74e547192461d16e0b843c97cba6951d31d556aed.
The fixed prefix helper is1572350..15723a4,84 bytes/37 rows,body
b2b1ff7af9c92df0857e5a876f7303e4d7ece768781101580da0d3389efa7382.
The fixed long-prefix counter is15796c0..1579c8b,1483 bytes/365 rows,body
13c5b0904bd66520b303cc5513d2cf7fed55c20298a5bef6a979f81be0083f35.
All three actual full raw listings were read before new padding Rust. This
is a mathematical native-transfer argument, not a PC/register evaluator or
captured execution. The published licensed libcore symbol correspondence is
corroboration, not a premise identifying original source/compiler or ABI.

## Admitted proxy and ordinary-call domain

The context has observed data/table words at+0/+8 and an eight-byte tail word
at+16. Its low32 are flags, next16 width, and final16 an uninterpreted quantity
usually labeled precision. These are observed widths/offsets, not recovered
Rust types or layout identity. The incoming sign is the full ESI unsigned32:
zero versus nonzero. Input prefix is an immutable valid UTF8 string and digits
an immutable readable byte slice. Both lengths are<=isizeMAX. The digit bytes
are forwarded as a raw opaque slice; no downstream UTF8/rendering contract is
asserted. Prefix pointers are valid/nonzero even for an empty string. Memory,
code, live frames, contexts, inputs and return storage are valid, separated,
nonwrapping and unchanged except for the declared synchronous callback cells.
Callbacks return normally and preserve the ordinary call/save roles.

The chosen safe proxy uses Cell words for context data/table/tail and stable
method cells in tables. A supplied callback may update those cells and return
any rawu8. It cannot mutate input/code/frame storage. The trace observes only
direct char/str requests, pre-action context cells, raw replies and final cells;
other callback internals, physical output, hidden registers, fault/unwind and
raw pointer identity/private ABI are outside the projection. A char request
contains the observed rawu32 argument without inventing a renderer.

## Prefix measurement, including the complete long helper

Define P(b)=0 for byte80..BF and1 otherwise. For a valid UTF8 string, every
Unicode scalar has exactly one noncontinuation byte, so sumP equals its scalar
count. This is scalar count, not display columns or encoded byte length.

In the main body prefix counting occurs only with flags bit23 set. A length0
prefix counts0. Length1..3 uses the signed-byte >=C0 comparison: signedC0=-64,
so it is exactly P. For lengths4..31, m=length&1c is4*floor(length/4).
The unrolled blocks load each pair of bytes within the firstm bytes exactly
once, stopping after the actual4/8/12/16/20/24/28 boundary. No load exceeds
the prefix. The scalar tail then counts length-m remaining bytes.

The pair transform is exact: signed PCMPGTB against the real BF,BF,zero... mask
produces indicators for the two loaded bytes only. UNPCK/SHUF D4 and AND with
the actual qword mask[1,1] place those two indicator bits in separate64-bit
lanes. Adding the pair vectors and horizontally summing their lanes counts
all bytes in the four-byte groups. Each count<=31, so no integer overflow or
cross-lane carry is involved. The real constant bytes and all source-relative
data fields are bound by the native admission.

For length>=32, main calls exactly the fixed1483-byte helper through actual
RELA slot5770628. This helper has no calls. In its actual caller domain, let
a=(-address) mod8,0<=a<=7. Because length>=32 and the readable interval does
not wrap, address+7 and the aligned address are representable. Set q=length-a,
t=q mod8 and w=floor(q/8). Then q>=25, so the helper's short-whole-input
fallback is unreachable from this call. Its memory interval partitions into
the firsta bytes, w complete8-byte words, and the lastt bytes. The small prefix
and tail use the same pair/SIMD or signed-scalar P rule. The tail mask
7ffffffffffffff8 equals roundingq down to8 because q<=isizeMAX.

For an8-byte word x, the exact indicator word is

    K(x)=((~x >>7)|(x >>6)) &0101010101010101.

The low bit of each byte is (~its bit7)|its bit6, exactly P; the mask removes
all cross-byte shifted bits. Native SIMD applies this equation independently
to64-bit lanes. At each outer iteration the word batch is min(w_remaining,192).
The32-byte groups cover floor(batch/4)*4 words; the128-byte unrolling merely
partitions groups four at a time. Every vector load falls in these complete
groups. A final1..3 words is possible only in the last batch, since192 is a
multiple of4. Its scalar-word K expressions cover exactly those words.

Every accumulated byte lane contains at most192 one-bit contributions, below
256, so packed64-bit additions cannot carry between byte lanes. Reduction
with00ff00ff00ff00ff pairs the eight byte counts into four16-bit lanes, each
<=384. Multiplying by0001000100010001 puts their sum in the top16 bits;
the sum<=1536<65536, so no coefficient carry changes that result. Low64 IMUL
and unsigned low multiplication agree modulo2^64. Adding the batch count to
the preceding prefix/tail/batch total is exact because the total<=length.

The outer word count decreases by a positive batch size, proving termination.
All8 address alignments,0..7 prefix/tail bytes,32/128-byte unrolling and every
192-word batch boundary are covered by this argument. The helper therefore
returns sumP for the complete input interval in its actual >=32 caller domain.
No opaque long-prefix counting dependency remains in the main relation. This
does not claim an independently qualified standalone helper domain with
arbitrary forged pointers or lengths beyond the admitted slice range.

## Sign, visible length and selected padding

Sign0 always selects '-' and adds1 to the measured length. Every nonzero
sign selects '+' exactly when flags bit21 is set; otherwise the internal
110000 sentinel means no sign request and adds0. Bit22 does not control this.
The prefix contributes scalar count only with bit23. Digits always contribute
their raw byte length. Let s be the resulting sum and W the widthu16. The
slice bounds ensure s<=2*isizeMAX+1=2^64-1, so the observed64-bit sums do not
wrap. The width is read after the pure prefix count, before any writer callback.

If s>=W, no padding is selected and the zero flag is ignored. Otherwise the
gap d=W-s satisfies1<=d<=65535. With bit24 clear, alignment bits29..30 select
left countL by the actual four-entry table:0->0,1->d,2->floor(d/2),3->d.
Right count isR=d-L. The raw fill argument is flags&1fffff. The trace order is
L fill-char requests, optional sign, optional prefix, one digits-str request,
andR fill-char requests. Empty digits still cause that str request.

With bit24 set and d>0, the trace instead requests optional sign/prefix, d zero
chars(rawu32 value30), then one digits-str request. Alignment/fill are overridden
for this invocation. This is sign-aware zero placement after sign/prefix, not
ordinary fill before the prefix. All local quantities are computed before the
first callback; later callback changes to flags/width do not recompute layout.

## Prefix helper and exact callback dispatch

The84-byte helper requests a char exactly when sign!=110000. If that char
returns any nonzero low byte it returns canonical1 and skips the prefix. After
success/no sign, prefix presence is tested by pointer-nonzero, NOT length.
Thus an enabled empty valid prefix invokes write_str(empty). Disabled prefix
is represented by main zeroing the pointer and causes no prefix call. With a
present prefix the helper tail-calls the live str method and forwards its raw
low byte; absent prefix returns0. Main normalizes a nonzero helper result to1.

Every main path caches the original context data/table identity before its
first writer callback. Every subsequent direct request uses those cached
identities, even if callbacks mutate the context's data/table cells. Method
slots themselves are live: the char method is read at each char dispatch and
the str method at each str dispatch. A sign callback can change the subsequent
prefix method; a prefix callback can change the digits method; a fill callback
can change the method for the next fill. The fixed helper also preserves its
passed data/table identities while reloading the later str slot.

## Temporary zero-padding state and restoration

The zero-padding branch saves the complete initial QWORD tail at context+16,
then writes only its low32 flags to

    (old_flags &9fe00000)|20000030.

This selects fill'0'/right alignment while preserving the observed high flag
bits. The original width/precision high32 remain until a callback changes them.
All zero-path callbacks see the current temporary/mutated tail word. Only
after sign, prefix, all zeros and digits ALL return0 does main restore the
entire saved QWORD. That restoration overrides callback changes to flags,
width and precision. It does not restore data/table cells or method cells.

Any zero-path callback error returns1 immediately WITHOUT restoring that
QWORD. The remaining state is the CURRENT word, which can include supplied
callback mutations; it is not always merely the initially installed temporary
flags. Ordinary padding and no-padding paths do not install/restore this word.

## Return bytes, loop bounds and error order

Every return value in this proof refers only to lowAL, not the whole EAX/RAX.
Only the no-padding final digits request is a main tail call forwarding every
raw lowAL byte unchanged. All earlier errors and all errors in either padding
mode return canonical1; completely successful padding returns0. The helper's
own raw prefix tail result is tested and normalized by main before any digits.

Leading and zero fill loops use16-bit countdowns for counts<=65535 and issue
exactly the requested count. Trailing fill starts with low counterFFFF; after
its jth callback the low counter isj-1. If that callback fails withj<=R, the
final comparison j-1<R returns1, INCLUDING failure on the last requested fill.
After allR successes, the loop exits before an extra callback, installs R for
the final comparison, and returns0. The split casesR=0 and maximum65535 are
covered without wrap-driven extra calls. All loops are finite in the admitted
width domain. This closes every direct writer route and normal return.

## Fresh authority, exact encoding and limits

The independent authority froze11150 distinct complete inputs before new Rust,
seal f280241cfed45a374378e9af99f2247f44d22ed3143550a9421efe5d71a54f6a.
It uses Unicode len(str), integer layout and supplied callback cell transitions,
not raw instruction interpretation. Cases include every align/selected-flag
combination, all256 raw replies at actual writer stages, empty requests,
noncanonical nonzero sign values, retained other flag bits, context/method
mutations, scalar-versus-byte prefix counts, long prefixes at all8 requested
owned alignments, and width65535/final-fill failures.

Its1086315 semantic callback observations are encoded as30343 adjacent exact
RLE groups. Each callback still occurs and applies its sparse ordinal script;
only adjacent IDENTICAL complete observation records are grouped, with exact
counts and total callback count. This is a lossless encoding of the declared
request/state observations, not target machine/output-byte normalization. The
corpus's largest case makes65536 calls; this is a corpus measurement, not a
claim that no admitted empty-prefix case could make65537 calls.

The Cells, tokens, callback scripts, numeric alignment observation and trace
encoding are chosen safe interfaces. No original struct/type/ABI, raw pointer
identity, hidden register, original compiler/machine bytes, physical writer or
full-node rendering behavior is established. All full-component gates remain
false. A separately compiled Rust implementation and corruption controls are
still required before claiming this chosen interface implemented and tested.
