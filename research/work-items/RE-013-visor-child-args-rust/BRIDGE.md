# Conditional native-to-safe-value bridge

Target is only Visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`. Coordinates are linked ELF virtual addresses. Complete native proofs are reused, not replaced by passing fixtures:

| Credited scope | Extent | Normal relation used |
| --- | --- | --- |
| #1029 validator | 0x49b560..0x49b757, 503 B / 143 rows | canonical UTF-8 iff success; success returns original span |
| #1029 actual adapter | 0x48dc00..0x48dc43, 67 B / 15 rows | descriptor+8/+16 to validator; tag0 returns same pointer/length |
| #1040 collector | 0x61da10..0x61dd6c, 860 B / 220 rows | finite ordered prefix, exact byte copies, pointer-zero stop |
| #988 caller context | 0x5b9070..0x5b92a6, 566 B | only selected descriptor/call/copy corridor below |

The three complete value bodies total 1430 B / 378 rows. The caller is full byte/FDE context, **not a new full-extractor theorem**. Its earlier table construction/hash/probe and later cleanup remain outside the composed result. All new native outputs retain those roles explicitly.

## Actual selected caller

The upstream search corridor compares candidate length with 10 at 0x5b9199; its 8-byte XOR constant at 0x5b9163 is `child-ar`, and its 2-byte XOR at 0x5b91b4 is `gs`. Their OR-zero branch at 0x5b91be enters 0x5b920a. This is an actual selected-name witness, not a recovered CLI grammar or proof that table lookup terminates/finds every key.

On entry to 0x5b920a, let R9 designate the selected candidate, P be current RSP, and O be preserved RBX (the original output address). The native loads start=[R9-24] and N=[R9-16]. LEAs at 0x5b9212/16 form end=start+24*N using machine arithmetic. The bridge requires the nonwrapping exact interval premise **before** interpreting it; the instructions alone do not establish it.

Stores at 0x5b921a/1f/2b place (start,end,callback) at [P+24,P+48). The actual RELATIVE slot 0x7e6aa0 selects adapter 0x48dc00. The call at 0x5b9238 supplies result P and argument record P+24 to 0x61da10. On its conditional ordinary return, 0x5b9241..0x5b925a copies its three raw words to O+0/+8/+16. The independent BPL store at O+24 precedes those copies but is not implemented or assigned a public flag effect here.

The selected theorem ends at 0x5b925a **before** cleanup call 0x5b9262 -> 0x5b3330. It does not claim the whole extractor returns, preserves allocations through cleanup, or yields process argv. Native byte values are related at the collector return / immediate copy endpoint only.

## Complete input and frame domain

Require N>=0, 24*N<=2^63-1, a representable nonwrapping end=start+24*N, and an immutable readable descriptor interval. Each visited nonnull span has 0<=length<=2^63-1, an immutable readable nonwrapping byte interval, and canonical UTF-8. For an empty span no byte read is required. The safe mapping's None is only pointer0,length0. Descriptors after the first stop are not read; their existence as interval storage is still part of the native descriptor premise.

The result24 and positive allocated outputs are writable and do not alias immutable descriptor/payload/image storage or active frames/return addresses. Input byte spans may alias one another if they remain immutable; no disjoint-input requirement is invented. Fresh outputs are mutually disjoint and disjoint from all inputs. Image bytes, tables and selected relocated bindings equal the authenticated capture and stay immutable.

Let collector-entry RSP=S, with ordinary SysV alignment S mod16=8. Its six pushes and 72-byte locals use [S-120,S), and its original return slot is [S,S+8). Each callback is entered at Sa=S-128. Adapter locals/result, nested CALL slot, validator saves and callback return together occupy [Sa-56,Sa+8)=[S-184,S-120). Thus the **combined** collector/adapter/validator active interval is [S-184,S+8). Ordinary valid hardware call/return contents and valid callee frames are separate assumptions; readable bytes alone are insufficient.

For the actual caller S=P-8, so that combined interval is [P-192,P). Result [P,P+24) and argument record [P+24,P+48) are adjacent but disjoint from it. Earlier extractor entry E satisfies P=E-0x4d8 (four pushes plus0x4b8 locals). The existing caller frame/return interval [P,E+8) must be valid, and the final output O..O+25 must avoid active frame/return storage, immutable inputs and the collector's allocated outputs. The argument/result are deliberate caller-local storage, not incorrectly assumed disjoint from their own caller frame. Immutable descriptor/payload/image regions must avoid all active stack writes and result/argument writes; a sufficient simple domain separates them from [P-192,E+8).

Every used callback, allocator and memcpy must preserve caller locals, RBX/RBP/R12-R15, restored caller RSP and immutable input/image. For the selected copy endpoint, RBX and RBP must retain O and the independent flag byte. The validator/adapter normal-success transfers are qualified by the full #1029 proof; arbitrary ABI conformance is not inferred from an address or function name. Allocator/copy calls have valid additional frames and cannot clobber earlier rows, payloads or live state.

## External dependency closure and exclusions

| Dependency | Observed binding / role | Required premise or boundary |
| --- | --- | --- |
| validator | RELATIVE0x7e4d28 ->0x49b560 | full credited conditional proof |
| callback | RELATIVE0x7e6aa0 ->0x48dc00 | full credited normal-success proof |
| allocator | RELATIVE0x7e4b60 ->0x70bf30 | each used positive request returns fresh valid nonnull storage of at least requested size, finitely and with frame/register preservation |
| byte copy | GLOB_DAT0x7e4b68, symbol6 memcpy | finite exact nonoverlapping copy and preservation; symbol does not prove runtime interposition/implementation |
| invalid UTF-8 helper | RELATIVE0x7e4cb8 ->0x49ab50 | call boundary only; ordinary fallthrough0x48dc43 is open |
| length/allocation error helper | RELATIVE0x7e4b40 ->0x2beaf4 | excluded by length/allocator domain; no noreturn assumption |
| growth | direct0x61dc37 ->0x620740 | proved unreachable on every admitted append; not reconstructed |
| deallocator / unwind | 0x7e4b80 ->0x714530, final0x7a6820 | cold/error context only; no cleanup ownership or error-return theorem |
| earlier/later caller helpers | upstream construction/hash/probe and cleanup0x5b3330 | outside selected corridor; no end-to-end CLI policy |

The native domain gives the allocation success externally; Rust standard allocation is a separate host behavior. Native output raw sentinels (0,8,0) and empty row(0,1,0) are **not** copied into safe pointers or claimed as Rust layouts.

## Value induction

#1029 proves canonical UTF-8, including ASCII00, with bounded wide ASCII reads, a decreasing cursor/phase measure, complete multibyte guards and first-invalid/truncated protocol. The actual adapter has success only for tag0 on that domain and returns the same span; it does not add a NUL or whitespace predicate. Invalid input enters the opaque error boundary, so the bridge makes no native collection-error claim there.

For N=0, collection branches at0x61da28 to raw empty result with no callback. For N>0, the callback at0x61da34 is followed by the pointer test0x61da37 **before** length inspection. A zero pointer yields no rows. Otherwise, length0 takes0x61dab7 with row pointerword1 and still appends one empty row. A positive length requests and copies exactly that many bytes at0x61da8f/aa; there is no extra terminator.

Let M=N-1. Exact interval arithmetic gives remaining R=24*M; SHR3 and multiplication by0xaaaaaaaaaaaaaaab recover M since3*K=1 modulo2^64 and M lies in range. CMP/CMOV selects max(3,M), then the request is24*(max(3,M)+1)=24*max(4,N). Its guards follow from24*N<=2^63-1; this capacity statement applies only after the first nonzero pointer, not immediate stop.

Before later index j, exactly j prior rows contain same-byte copies and j<N<=C=max(4,N). The callback visits start+24*j once. A zero pointer returns that prefix without reading later descriptors. Otherwise length0 or positive length produces the corresponding exact row; j<C excludes both growth comparisons. Stores at0x61dc46/50/55 occupy row j, then increment j. The next fixed-interval cursor either equals end or is the next valid descriptor. Thus the loop terminates after at most N callbacks under finite ordinary callee premises.

Consequently the safe None/Some mapping returns exactly the prefix of canonical strings before None, preserving empty/NUL and all original bytes/order. Input mutation after the host call or dropping its buffers must not alter the owned return values; this tests the chosen ownership representation, not native allocator identity. New refusal of invalid UTF-8 is a safe boundary around a native path not qualified by this composition.

## Canonical scalar-language connection

The independent oracle ranges over scalar integers, not byte decoder cases. Scalars0..0x7f encode as one byte;0x80..0x7ff as two;0x800..0xffff excluding0xd800..0xdfff as three;0x10000..0x10ffff as four. Splitting the integer into high bits and successive six-bit groups gives exactly C2..DF, E0..EF and F0..F4 leads, each continuation80..BF. The lower bound0x800 forces E0's second byte A0..BF; excluding surrogates forces ED's second80..9F. The four-byte lower bound forces F0's second90..BF, and the upper bound forces F4's second80..8F. All other permitted second-byte groups are80..BF.

Conversely these lead/second restrictions and remaining continuation bytes recover a unique scalar in the indicated range with shortest width. Therefore the enumerated scalar-prefix language equals the complete native #1029 grammar, including NUL and excluding overlong/surrogate/out-of-range encodings. Unique lead widths make concatenation unambiguous. Standard-library UTF-8 admission is used only through that language contract; native fast ASCII alignment and original compiler identity are not transported into Rust source. The full1,112,064-scalar finite certificate checks the independent construction; finite production corpus comparisons separately test the pinned host implementation on108,604 synthetic collection inputs.
