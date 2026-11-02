# Conditional text-provider and caller contract

All addresses are node #115 linked ELF VAs. `T=2^63`; words are unsigned
64-bit unless a signed test is named. `J` denotes the parser context, `O` an
output pointer, and `(C,P,H,N)` the four words returned by the provider. These
are descriptive roles, not recovered Rust types or a public protocol schema.

## Domain and meaning of the result

Execution enters at the recorded FDE start and follows ordinary instruction
edges and ABI-conforming normal call returns. No out-of-FDE reentry,
concurrent mutation, exceptions, stack corruption or self-modifying code is
included. Input/output/context/stack storage is accessible, suitably aligned
where required, and disjoint except for explicitly described argument views.
The input byte interval is valid and nonwrapping; `0 <= cursor <= length <=
2^63-1`. This bounds the local cursor arithmetic as well as the loads.

Callees preserve callee-saved registers and all live memory outside their
designated output/context effects. In particular, numeric/error helpers do
not modify the live ring, input backing bytes, context mode/depth fields or
caller prefix. The opaque first-field decoder preserves mode/depth and live
outer locals outside its designated 20-byte destination and parser/output
effects. Allocator imports return valid storage of the requested size
and preserve the previously initialized prefix. Successful numeric helper
returns initialize the result fields read by their caller. These are explicit
premises. The packet does not recover the opaque helper implementations or
derive pointer validity from a nonzero pointer. Relocation bindings describe
the linked image, not a runtime pointer observation.

Ordinary error-factory returns, especially `0x1d75420`, are additionally
assumed to be nonzero pointers to valid readable error objects for the
selected consumers. This is an opaque-callee premise, not a recovered fact.
The closer forwards that factory's RAX unchanged; without this premise an
invalid delimiter could return zero and be interpreted as completion.

Under those premises, successful provider parsing admits the prefix grammar

```text
W '[' W (I (W ',' W I)*)? W ']'
W := zero or more bytes 09, 0a, 0d, 20
I := '0' | [1-9][0-9]*, with mathematical value <= 2^64-1
```

The provider leaves the cursor immediately after `]`; trailing input is not
checked there. Successful growth returns a contiguous initialized prefix of
`N` integer words with `H=0` and `N<=C`. The ordering wrapper then requires
strict unsigned increase. This is a conditional local normal-return result,
not a guarantee of allocation, termination or successful parsing of every
arbitrarily large valid spelling.

## 1. Provider entry, separators and depth

`0x1e29f50` receives `O` in RDI and `J` in RSI. It uses byte pointer `J+0x18`,
length `+0x20`, cursor `+0x28`, mode byte `+0x48`, depth byte `+0x49`.
The mask at `0x1e29f85` is `0x100002600`; the preceding byte bound and BT admit
exactly the four `W` bytes. Skipped bytes update the cursor. Exhaustion
selects raw error class 5. The next byte must equal `0x5b` at `0x1e29fcf`.

Mode nonzero bypasses both depth decrement and restoration. For mode zero:

| Initial depth byte | Local result |
| --- | --- |
| 0 | Branch at `0x1e29fe6` calls the failure endpoint before decrement |
| 1 | DEC stores 0 at `0x1e29fee`; branch selects class `0x18`; no restoration |
| 2..255 | DEC stores 1..254; normal loop exit restores the original byte at `0x1e2a13e` |

Thus byte wrap from 0 to 255 is not an admitted normal path. The restoration
checks `0xff` before INC. Under the stated preservation premise it is not
reached with `0xff`; arbitrary helper mutation is not ruled out by this proof.
Opening-byte cursor increment also has an explicit zero/failure check. The
valid input interval prevents that increment from wrapping.

The sequence descriptor is `{J, first=1}` at stack `+0x30/+0x38`.
`0x1dbe700` returns two active bytes: byte0=1 selects error payload at +8;
otherwise byte1 is the presence flag. A closing `]` produces no next item
without consuming it. A first item clears `first`; later items require `,`.
After a comma, EOF selects class5 and `]` selects class`0x15` (trailing comma).
A missing comma selects class7. Initial sequence exhaustion selects class2.
All successful presence paths write byte0=0, byte1=1; no arbitrary enum-domain
assumption is needed for these local stores.

Under the nonzero error-factory premise, `0x1d77cf0` skips `W` and consumes
exactly `]` on its zero return. Initial exhaustion (including initial skipped
whitespace) selects class2. After a comma, EOF or exhausted whitespace selects
class`0x16`; comma followed by `]` selects class`0x15`; other remaining data
selects class`0x16`. Its error factories are opaque, so these are raw class arguments,
not recovered diagnostic names. The closer runs on both loop success and
ordinary loop error; it is not a full-input-exhaustion check.

## 2. Numeric admission, including the rejected alternate paths

`0x1d772e0` returns `(AL=0,RDX=value)` on its accepted path and a low-bit-set
status plus error payload otherwise. It skips the same `W`, accepts an initial
digit or consumes a minus sign, then invokes `0x1d76380` with EDX exactly 1
(positive spelling) or 0 (minus spelling). Other leading bytes enter a type
error helper. The parser returns a complete qword tag and a payload at +8.

At `0x1d77380/0x1d773b7`, full tag3 propagates an error. At `0x1d773c2`, low
tag1 is accepted. Low tag2 is accepted only if `TEST RDX,RDX; JS` does not
branch. All other tags enter type rejection. The low-32-bit tests do not
create extra successful tags here: the inspected producers store complete
qword tags from the finite set 0,1,2,3. Normal error helpers' final returned
payload is not reinterpreted as a successful integer.

`0x1d76380` consumes a first digit. Zero followed immediately by another digit
selects class`0x0d`. A nonzero first digit must be 1..9. Let `M=2^64-1` and
`q=floor(M/10)=1844674407370955161`. The loop admits another digit `d` only if
`a<=q-1`, or `a=q && d<=5`. Therefore `10*a+d<=M`. Its ADD also has a carry
failure branch at `0x1d76435`. Digits are zero-extended bytes; no sign-extended
digit can enter the accumulator. Above that bound, the floating fallback
does not produce an integer tag, regardless of its numerical result.

The complete `0x1d75ea0..0x1d761e2` classification body gives the following
partition. Floating arithmetic need not be reproduced to prove its tag.

| Path / decisive instructions | Stored outer tag | Accepted by element wrapper? |
| --- | --- | --- |
| No `.`/`e`/`E`, DL=1, `0x1d75f05..0x1d75f16` | 1, payload accumulator | Yes |
| No suffix, DL=0, `NEG` result has sign bit, `0x1d75f19` → `0x1d76008` | 2, negative payload | No: payload sign bit set |
| No suffix, DL=0, `NEG` result sign clear (including magnitude0 and magnitude>2^63) | 0 via `0x1d75f55` → `0x1d76165` | No |
| Initial exponent helper `0x1d75ee4` returns byte0=0 | 0 via `0x1d75f5a` | No |
| Initial exponent helper returns byte0!=0 | 3 at `0x1d75ef9` | No |
| Fraction's exponent helper at `0x1d76031` | 0 via `0x1d76160`, or 3 via `0x1d76112` | No |
| Local fraction calculation at `0x1d760f4..0x1d76110` | 0 via `0x1d76160` | No |
| Fraction overflow helper at `0x1d76185` | Same byte0 envelope, 0 or 3 | No |
| Local fraction/error construction, `0x1d7612e` and `0x1d76190` | 3 via `0x1d76112` | No |
| Integer overflow helper at `0x1d7646d` | 0 at `0x1d764e0`, or 3 at `0x1d76483` | No |

Magnitude `2^63` negates to itself and selects the sign-set tag2 case.
Magnitudes 1..`2^63-1` also select tag2 with a negative payload; magnitudes
above `2^63` and `-0` select tag0. Therefore even `-0` is excluded. The
classification tag stores use zeroing 32-bit register writes or immediate
qword stores, so stale high bits cannot convert a floating envelope into an
accepted tag. No claim is made about the floating value, error object,
termination or cursor effects inside those opaque helpers.

## 3. Ring induction and allocator boundary

Provider initialization `0x1e2a014..0x1e2a02e` gives `(0,8,0,0)`. With no
elements, the pointer8 is only a sentinel; the ordering context makes no
element load for `N=0`. At each successful element, the provider grows iff
`N==C`, increments N, computes `(H+oldN) - (C if H+oldN>=C else 0)`, and stores
the parsed word at that index. It does not sort or deduplicate.

The loaded growth slot `0x64e2620` has a symbol-zero RELATIVE relocation to
`0x4560af0`; its inner slot `0x64ea7b8` similarly reaches `0x43bbcd0`.

1. Reserve chooses `Cnext=max(4,2*C)` at `0x43bbcdd..0x43bbceb`.
2. It passes old capacity, old pointer, Cnext, alignment8 in R8 and width8 in
   R9 to `0x43bd550`.
3. The adapter uses unsigned MUL for width*Cnext and rejects either multiply
   overflow or `8*Cnext > 2^63-8` (`0x43bd564..0x43bd588`). Raw result tag1
   selects the reserve failure endpoint; only tag0 reaches pointer/capacity
   replacement at `0x43bbd10`.
4. For this alignment/size, zero old capacity selects slot`0x64df480` and
   nonzero old capacity selects slot`0x64df588`. A null return produces tag1.
   These callees remain opaque. Their nonzero return is not proof of storage
   validity; the allocator/prefix-preservation premise supplies that fact.
5. Growth preserves old C in R14, then compares H with `oldC-N`. At full growth
   H=0 and N=oldC, so `JBE` at `0x4560b12` goes directly to RET. Neither the
   memmove path nor the memcpy tail path runs in this induction.

Inductively H stays zero and oldN<C after any successful growth. The append
index is therefore oldN; its initialized prefix grows by one word. Starting
from C=0, normal successful capacities are powers of two 4..`2^59`; a request
for `2^60` violates the adapter's byte bound. In particular C cannot collide
with T, doubling cannot wrap on this domain, `N<=C`, and `8*C<=2^63-8`.
No ordinary parser-error result is promised for allocation failure; it enters
the distinct failure endpoint. No hard input-length/policy cap is inferred
from this mathematical upper bound.

The other growth branches are retained in the full FDE and CFG. Their actual
relocation symbols are `memmove` and `memcpy`; the theorem does not depend on
executing them or on a global wrapped-ring reserve implementation.

## 4. Provider result, cleanup requests and existing ordering

| Provider path | Active result / request |
| --- | --- |
| Sequence ends, closer returns0 | Four words C,P,H,N at O; RAX=O |
| Sequence/element error | If C!=0, request slot`0x64df4a0` with `(P,8*C,0)`; retain first error for decoration |
| Earlier error and closer also errors | Dispose the later close error through `0x1daeb80`, then request 40-byte object cleanup; select earlier error for decoration |
| Built ring, closer errors | If C!=0, request `(P,8*C,0)` cleanup, then decorate close error |
| Ordinary final error | O[0]=T, O[8]=error payload; O[16..32) inactive/unestablished |

Later error paths above pass through the selected decoration body. Early
provider exhaustion and depth1 instead call `0x1d75420` at `0x1e29fc5` and
jump directly to `0x1e2a1c7`; no selected decoration call is established for
those paths. Nothing here proves whether the opaque factory decorates them.

`0x2cf8390` returns an error pointer unchanged when its +0x18 word is nonzero;
otherwise it calls `0x1d77b20`, requests 40-byte old-object cleanup and returns
the new pointer. Thus first-error preference means selection before
decoration, not guaranteed pointer identity. Error structures and physical
memory release are not recovered.

Ordering body `0x2923da0` is **credited from PR #1003**, not new recovery.
Its call at `0x2923daf` receives this provider result. NEG/JNO singles out T;
that case propagates O[0]=T and O[8] without ordering. Other normal results
now satisfy the previously assumed metadata/storage conditions under the
allocator premises. Its two JB loops enforce the existing strict unsigned
neighbor relation. For H=0 the initialized prefix is contiguous. N=0/1
requires no comparison; duplicates or descending values reach `0x2923ea4`,
the source-associated invariant failure call followed by UD2. They do not
return the parser-error sentinel on the normal local path.

The prior Location relocation at `0x6483ff8` binds path `l1/src/nonce_set.rs`,
line141, column13. The literal prefix at `0x7c958c` is 15 bytes. The call's
ESI=31 is retained as a raw argument and is **not** called that prefix's
length. Source association is not source-type identity.

## 5. Concrete immediate caller

Full caller `0x1ddf3b0..0x1ddf7bf` receives an outer sequence descriptor in
RSI and its output pointer in RDI. The entry next-item call distinguishes
error, no next item, and presence. Presence requires a new `[` and performs
the same depth operation. Its first inner element invokes opaque
`0x1e3e180` with a descriptor for a previously zeroed 20-byte local buffer;
this packet does not name that field as an address. Its second inner element
calls ordering at `0x1ddf606`. Missing first/second elements pass raw indices
0/1 to `0x2cf1300`; error-message semantics are unassigned.

The caller's additional outer depth decrement means an ordinary successful
second-provider path needs initial depth>=3 in mode0. Depth1 fails at the
outer decrement; depth2 reaches inner provider depth1, which stores0 and
returns its depth error. Subsequent outer restoration does not establish a
successful parse or restore every failed nested parser to its entry depth.
Mode nonzero bypasses both selected levels' depth accounting.

After a successful ring return, the caller restores its depth and invokes
the closer. Under the nonzero error-factory premise the closer requires `]`,
so extra third inner data fails the
ordinary completion path. Earlier errors take precedence over a later close
error before decoration, as in the provider. A close error after a built ring
requests `(P,8*C,0)` cleanup iff C!=0.

| Caller normal result | Active output |
| --- | --- |
| No next item | qword at O+0x18=T; other words unestablished |
| Ordinary error | qword at O+0x18=T+1; payload at O+0 |
| Completed pair | first-field bytes at O[0..20); C at +0x18, P at +0x20, H at +0x28, N at +0x30 |

All selected normal returns set RAX=O. Success copies 24 prefix bytes, but
only the first20 were initialized by the zeroing/first-field path. Four
padding bytes at O+0x14..+0x17 are copied without established initialization;
they are not an additional field. Success C cannot collide with T or T+1.
This caller contract is a downstream use of the recovered provider domain,
not evidence of a public nonce endpoint or anti-replay policy.

## 6. Complete structural and exceptional census

The retained GNU text covers every byte of all12 FDEs; independent LLVM
partitions agree. `cfg.tsv` records all362 basic blocks, including landing
pads, and `transfers.tsv` all315 transfers. Calls have conditional normal
return edges, including explicit outside-FDE fallthrough where a last call
would return past the extent. Such paths are not silently called noreturn
and are excluded from the local normal-return theorem. There are no local
computed jump tables. The only register call is the growth slot loaded into
RBX; the only RIP-indirect tail transfer is the unselected growth memcpy path.

`records.json` keeps all23 LSDA call-site rows: provider9, ordering3, caller9,
decoration2. Every interval boundary and nonzero landing VA is checked
against decoded boundaries. Landing pads remain in the native text and CFG:

| Owner | Nonzero landing targets / local evidence |
| --- | --- |
| Provider | `0x1e2a25f` conditionally requests ring cleanup; `0x1e2a21e` requests 40-byte object cleanup; `0x1e2a239/0x1e2a249` call opaque `0x1d92e50`; `0x1e2a259` calls a failure slot |
| Ordering | `0x2923ebf` conditionally requests `(P,8*C,0)` cleanup then resumes |
| Caller | `0x1ddf77a` requests object cleanup; `0x1ddf795/0x1ddf7a4` call opaque `0x1d9be20`; `0x1ddf7b9` calls a failure slot |
| Decoration | `0x2cf83ca` requests 40-byte cleanup then resumes |

These are LSDA rows and decoded landing-pad instructions, not an execution
of the unwinder, interpretation of action/type chains, complete ownership
closure, or proof that memory was physically freed.
