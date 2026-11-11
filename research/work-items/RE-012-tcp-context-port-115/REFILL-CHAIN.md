# RE-012: selected refill chain and bitmap return on node #115

Task RE-012, following the allocator boundary reached by the transport-context
write analysis. Sole target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
Owned files: this packet only; no implementation or shared tooling change.

The [fresh-fallback supplement](FRESH-FALLBACK.md) stopped before preparation
at `0x63e9cd0` or direct allocation at `0x6364880`. This supplement follows
selected zero/one-item preparation, the following `0x63e9c40` wrapper, its
`0x6362190` worker, and the caller continuation through return. It also follows
the existing-head direct alternative, the preparation marker and metadata
helpers, and the worker's encoded bit-count helper call.

The central new result is a conditional connection from a selected bitmap bit
to the pointer written into the cache and returned to the original caller.
Zero requested items still cause state changes. A wrapper status byte of 1
does not itself exclude a null pointer; the caller increments its cache count
before testing that pointer. These distinctions matter when bounding writes
from the surrounding transport helper. Complete allocation ownership and
preservation of the outer transport word are still unproved.

## Evidence identity and scope

[refill-spec.json](refill-spec.json) pins code hashes, 33 instruction anchors,
transfer targets, four relocations, 22 selected RIP-relative data operands and
the selected store union. [refill.py](refill.py) authenticates the full ELF,
checks those bindings and exports [refill/records.json](refill/records.json).
GNU, LLVM and Capstone exports retain raw bytes and instruction boundaries;
no normalization masks are applied.

| Entry | Exclusive end | Bytes | Instructions | Boundary basis |
| --- | --- | ---: | ---: | --- |
| Caller `0x6353a70` | `0x635582b` | 7,611 | 1,691 | Exact FDE |
| Preparation `0x63e9cd0` | `0x63ead4c` | 4,220 | 927 | Exact FDE |
| Take wrapper `0x63e9c40` | `0x63e9cc8` | 136 | 44 | Exact FDE |
| Worker `0x6362190` | `0x6362901` | 1,905 | 446 | Exact FDE |
| Direct alternative `0x6364880` | `0x6365142` | 2,242 | 499 | Exact FDE |
| Marker checks `0x63b6c50` | `0x63b6e64` | 532 | 142 | Exact FDE |
| Metadata mapper `0x63e94a0` | `0x63e9bf2` | 1,874 | 396 | Exact FDE |
| Bit-count interval `0x63f0960` | `0x63f09c2` | 98 | 27 | Encoded call target through RET; no containing FDE |
| Three import stubs | Entry + 16 each | 48 | 9 | PLT windows |

Total capture is **18,666 bytes / 4,181 instructions**, including the already
captured caller. This is context for selected paths, not a coverage denominator
or credit for closing every branch in these bodies. The bit-count interval
must not be promoted to an FDE-derived complete function.

Existing [ctxfeed evidence](../RE-001-node115-lu-ctxfeed/README.md) overlaps
preparation. Its five short exhibits (205 bytes) are revalidated against this
ELF. Its stated end `0x63ead50` includes four trailing INT3 bytes: the exact FDE
ends at `0x63ead4c`. This correction is recorded here without modifying the
original packet. Its broad caller census, previous tests and all-path prose
are not inherited as validation of this supplement.

## Caller identities and prerequisites

Use the prior selected small-size, eligible-state, exhausted-cache path:
`N<=4096`, the established TLS/base relation, valid class index `k<=231`,
the recorded global guards and a nonnull provider `E=QWORD[B+0x90]`.

```text
B = QWORD[FS:0] - 0x10a8
K = B + 0x358
A = B + 24*k
C = A + 0x360 = K + 24*k + 8
W = QWORD[0x6728868]
t = WORD[W + 2*k]
S = QWORD[0x6727a00 + 8*k]
```

`W` is a pointer read from the global cell, not the cell's address used as
the word table. Its BSS placement supplies no runtime pointer or table values.
Known offset identities, including C within B, are intentional. Non-aliasing
premises below exclude additional overlapping accessed regions, not these
established identities. Counter updates and reported deltas retain the
instruction's modular operand width; they are not nonnegative accounting
assertions.

| C-relative location | Width | Observed use in this selection |
| --- | ---: | --- |
| `+0` | 8 | Pointer-array cursor L |
| `+8` | 8 | Count drained into shard statistics and incremented by caller |
| `+0x10` | 2 | First low-16 cursor bound |
| `+0x12` | 2 | Preparation bound |
| `+0x14` | 2 | End low-16 bound |

The incoming refill selection has `low16(L)==WORD[C+0x10]==WORD[C+0x14]`.
For the general helper formulas below define
`end=L+u16(WORD[C+0x14]-low16(L))`, with machine-width pointer arithmetic.
On this incoming selection `end=L`. Names such as cache, provider and shard
are inferred roles; these are not recovered source-level types.

The nonzero-table call sequence is encoded at:

```text
0x63541d1: prepare(B, K, C, k, 1)            -> 0x63e9cd0
0x63541eb: take(B, E, K, C, k, &status)      -> 0x63e9c40
0x63541f0: compare status with zero
```

The status pointer is caller stack `SS+0x40`. The selected caller passes the
same C to both helpers; ABI preservation, valid non-aliasing storage, stable
tables and absence of interference remain explicit premises across calls.

## Preparation: zero and one item

At `0x63e9d1f..0x63e9d37`, with `m=WORD[C+0x12]` and
`z=WORD[C+0x14]`, the effective item count is:

```text
p = ((m - z + 8*t) mod 65536) >> 3
```

The actual shift is **SHR R10W,3**, not a 32-bit shift. It sets ZF using the
16-bit result while retaining unrelated upper register bits. Later MOVZX
instructions narrow the saved value before it is used as an item count.
The result ranges from 0 through 8,191. In particular `t!=0` does not imply
`p!=0`: `t=1,m=z-8` gives zero. A shift or widening change would alter the
selected branches.

For `p=0`, the selected canary-success return has six local explicit stores
and no nested call or explicit object store. It leaves the preparation bound
unchanged. This does not describe the following worker's effects.

For `p=1`, the item-array start is `R=end-8*t`, and `X=QWORD[R]`.
Two dynamically sized local arrays each occupy 16 bytes on this path.
The two selected stack-probe OR writes are included in the store inventory;
the page-probe loops are not selected.

The call at `0x63e9d9c` passes `(R,1,S)` to `0x63b6c50`. The selected helper
checks that the qwords at `X`, `X+((S>>1)&~7)` and `X+S-8` all equal
`0x5b5b5b5b5b5b5b5b`. With valid readable locations, `S>=8` and all three
checks passing, it has two local explicit stores and no nested call or payload
store. The mismatch reporter at `0x63d9a80` remains outside this selection.

The call at `0x63e9e35` passes `(B,&descriptor,1,out)` to `0x63e94a0`, where
the descriptor holds the item count at `+0` and R at `+8`. For its selected
metadata-cache hit:

```text
tag = X & 0xffffffffc0000000
index = (X >> 26) & 0xf0
require QWORD[B+0x1b0+index] == tag
M = QWORD[B+0x1b8+index] + ((X >> 9) & 0x1ffff8)
H = sign_extend_48(QWORD[M]) & ~127
```

This helper writes M and then H into the same output slot, at `0x63e96f6`
and `0x63e9603`. Its selected path has no B-relative store or nested call.
Two prefetch operands are recorded separately, not counted as writes. Valid
metadata/cache identity and canonical accessible addresses are premises.

Preparation then obtains the following values, independently of any later
worker's choice of provider or shard:

```text
key = QWORD[H] & 0xfff
Ekey = QWORD[0x65096c0 + 8*key]
j = (QWORD[H] >> 38) & 63
J = Ekey + DWORD[0x6511780 + 4*k] + 224*j
D = QWORD[K]
drain_provider = QWORD[D+0x28]
```

The selected `pthread_mutex_trylock(J+0x40)` returns zero. It increments
`QWORD[J+0x38]`; when `[J+0x30]!=B`, it also increments `[J+0x28]` and stores
B at `[J+0x30]`. Both owner alternatives are retained.

For the selected matching drain provider and first matching item:

1. `[J+0x98]++`, `[J+0x80]+=QWORD[C+8]`, then `QWORD[C+8]=0`.
2. Form `v=((X-QWORD[H+8])*DWORD[0x6511820+4*k]) mod 2^64`.
   XOR bit `(v>>32)&63` in `QWORD[H+0x40+8*(v>>38)]` at `0x63eaa6f`.
3. Add `2^28` to `QWORD[H]`. The updated ten-bit field
   `(QWORD[H]>>28)&1023` must differ from both 1 and the dword at
   `0x6711b40+40*k+0x10` for this selected path.
4. `[J+0x78]++`, `[J+0x88]--`, `BYTE[J+0x68]=0`, then unlock `J+0x40`.
5. Subtract 1 from `DWORD[B+0x98]`, selecting a sign-clear result; no retained
   or separately collected items remain. Store `low16(end-8*t)` at `C+0x12`.

The full header increment is retained, including possible carries outside
the ten-bit field. A semantic name such as generation is not established.
The sign-clear result is the branch predicate, not proof of an initially
positive counter. Marker failure, metadata misses, contention, different
providers, grouped loops and the other header-value branches remain open.

## Wrapper request, worker and returned pointer

`0x63e9c40` saves `D=QWORD[K]` before calling the worker. It reads
`h=BYTE[D+k+0x34]`, zero-extends t, then performs a 32-bit SAR by CL:

```text
requested = t >> (h & 31)
worker(B, E, C, &W[k], k, requested)
```

The value is initially nonnegative, so this SAR has the stated unsigned
result. A byte value of 32 means shift by zero; there is no demonstrated
invariant restricting h to 0..31. The worker overwrites incoming RCX and
does not use that pointer argument on the selected paths.

The worker chooses `j=BYTE[B+k+0xa1]` when B and `[B+0x90]` are nonnull, and
forms `J=E+DWORD[0x6511780+4*k]+224*j`. Successful trylock and the two owner
alternatives have the same visit/owner writes described above. Equal J across
preparation and worker requires equal provider and shard identities; it must
not be inferred solely from their use of the same class index.

For **requested=0**, it skips the head/bitmap loop, but still:

- Adds zero to `[J+0x70]`, increments `[J+0x90]`, and adds
  `(QWORD[C+8],0)` to the two qword lanes at `J+0x80` and `J+0x88`.
- Clears `QWORD[C+8]` and `BYTE[J+0x68]`, then unlocks.
- Stores end at C and subtracts 1 from `DWORD[B+0x98]`, selecting a
  sign-clear result and successful canary check.

For **requested=1**, select an existing `H=QWORD[J+0xc0]`, a nonzero
`(QWORD[H]>>28)&1023`, and a nonzero first bitmap word `w=QWORD[H+0x40]`.
The selected body does not fetch another head or scan another bitmap word.
At `0x63624ee` it calls `0x63f0960` to count set bits in w. The requested-item
limit and nonzero w select one extraction:

```text
i = index of lowest set bit in w
stride = QWORD[0x6711b40 + 40*k]
Q = (QWORD[H+8] + i*stride) mod 2^64
QWORD[end-8] = Q
QWORD[H+0x40] = w XOR (1 << i)
QWORD[H] -= 2^28
```

The pointer write is at `0x6362658`, bitmap store at `0x6362665`, and header
store at `0x6362696`. The worker adds 1 to `[J+0x70]`, increments `[J+0x90]`,
adds `(old QWORD[C+8],1)` to the qword lanes at `J+0x80/0x88`, clears C+8
and J+0x68, then unlocks. It stores `end-8` at C, subtracts 1 from B+0x98
and selects the sign-clear/canary-success return. Q is not returned by this
worker as an allocation-result register; the following wrapper reads it.

The bit-count interval contains only integer register arithmetic followed by
RET: pair counts with mask `0x5555555555555555`, nibble counts with
`0x3333333333333333`, octet counts with `0x0f0f0f0f0f0f0f0f`, then 32/16/8-bit
folds and `&127`. No memory store, call or conditional branch occurs in the
98-byte interval. Scalar corroboration is separate from the retained bytes;
no target code is executed or emulated.

After the worker returns, the wrapper sets `BYTE[D+k+0x58]=1` in every
selected branch. It loads `L=QWORD[C]` and **QWORD[L] before testing the two
low-16 bounds**, so even the empty branch requires a readable cursor.

| Bound tests after worker | Explicit C changes | status | Return |
| --- | --- | ---: | --- |
| `low16(L)!=WORD[C+0x10]` | `[C]=L+8` | 1 | Loaded Q |
| Equal first bound, unequal end bound | `[C]=L+8; WORD[C+0x10]=low16(L+8)` | 1 | Loaded Q |
| Equal both bounds | None | 0 | Zero, regardless of loaded Q |

All three wrapper branches are recorded. Only the regular and empty branches
join the selected exhausted-cache zero/one-worker examples under the stated
stable-storage premises; the boundary branch is a conditional post-call
observation, not an additional demonstrated outcome of those examples.

## Joining the selected stages

Four arithmetic constraint sets use `t=1`, initial end low bits `0x1000`,
`m=end-8+8*p`, and `h=1-requested`, for p and requested each in `{0,1}`.
They demonstrate compatible count/shift/bound conditions, **not observed
runtime states or complete proofs that the allocator creates such states**.
The one-item preparation and worker premises above must also hold.

With the same shard in both stages, no alias/interference, nonnegative
post-subtraction counters and a nonnull generated Q for requested=1:

| Preparation items | Requested items | Final cursor | Final C+8 | Final C+0x12 | B+0x98 delta | Caller result |
| ---: | ---: | --- | ---: | --- | ---: | --- |
| 0 | 0 | Initial end | 0 | low16(end-8) | -1 | Null, errno 12 |
| 0 | 1 | Initial end | 1 | low16(end-8) | -1 | Generated Q |
| 1 | 0 | Initial end | 0 | low16(end-8) | -2 | Null, errno 12 |
| 1 | 1 | Initial end | 1 | low16(end-8) | -2 | Generated Q |

The equal first/end bounds remain unchanged. A one-item worker temporarily
sets the cursor to end-8; the wrapper's regular pop restores end. Preparation
with zero items leaves its initial m intact; with one item it writes the same
final low16(end-8). The worker always drains C+8; the original caller then
increments it only when wrapper status is 1.

For that same-shard selection, the net qword deltas are:
`J+0x38 += p+1`, `J+0x70 += requested`, `J+0x78 += p`,
`J+0x80 += initial(C+8)` exactly once, `J+0x88 += requested-p`,
`J+0x90 += 1`, and `J+0x98 += p`. If preparation handles one item, it leaves
`[J+0x30]=B`, so the subsequent worker must take its same-owner branch under
no interference. The two independently captured owner alternatives cannot
be freely combined into an impossible two-new-owner same-shard trace.

A narrower conditional return identity is also visible. Let preparation's X
equal `QWORD[H+8]`, let its mapped H be the worker's existing head, and choose
an initial header field 1, a class comparison value other than 2, and initial
bitmap `w=2`. Preparation's product v is zero, independent of the reciprocal
table value: it toggles bit zero, changes w to 3 and the header field to 2.
The one-item worker then selects bit zero, writes Q=X, and restores w=2 and
the original header. Marker, metadata and all other premises still apply.
This is a symbolic sufficient condition for returning that same address;
it does not establish arbitrary free/allocate inverses or erase the counter,
flag and cache side effects.

At the original caller, status 1 branches to `0x6353b4d`, which increments
`QWORD[C+8]` **before** the Q-null test at `0x6353b58`. Thus status 1 plus
null Q retains that increment and then stores errno 12. Status 0 goes directly
to the errno path without the increment. Nonnull Q rejoins the previous
mode-one accounting result, with both threshold outcomes retained. The
status-1/null branch is recorded conditionally; it is not asserted reachable
from the above valid-nonnull one-item selection.

## Zero-table direct alternative

For `t=0`, the caller instead invokes `0x6364880(B,E,N,k,0)` at `0x6354cda`.
The recorded `N<=4096` also satisfies this helper's `N<=0x3800` selection.
With B/E nonnull, the same provider-present shard selection, successful
trylock, an existing head with a nonzero ten-bit header field and a nonzero
first bitmap word, it uses the same `Q=base+lowest_bit*stride` relation.

The direct branch XORs that bit at `0x6364a57`, subtracts `2^28` from the
header at `0x6364a60`, selects Q nonnull, increments `[J+0x70]`, and adds
`(1,1)` to `J+0x80/0x88`. Those two ones are bound to the 16-byte rodata at
`0x455ff0`. It clears J+0x68, unlocks, skips the optional fill because the
caller passed zero, decrements DWORD B+0x98 with a sign-clear result and
returns Q. Both owner alternatives are retained.

No explicit C cursor/count writes occur on this selected direct path, and the
caller does not increment C+8 on this route. Its nonnull result rejoins the
same mode-one accounting continuation. A conditional caller-null continuation
is recorded separately from this selected nonnull callee return. This is not
proof of general direct-allocation success or ownership.

## Selected stores, verification and remaining gaps

| Selected path | Instructions before RET | Explicit store sites |
| --- | ---: | ---: |
| Caller status 0 / status 1 with null | 91 / 93 | 3 / 4 |
| Caller status 1 nonnull, no accounting call / with call | 105 / 109 | 9 / 9 |
| Caller direct null / nonnull / accounting call | 82 / 94 / 98 | 2 / 7 / 7 |
| Preparation zero | 38 | 6 |
| Preparation one, same / new owner | 251 / 253 | 41 / 43 |
| Marker one / metadata one / bit-count leaf | 45 / 63 / 26 | 2 / 2 / 0 |
| Wrapper regular / boundary / empty | 33 / 37 / 36 | 3 / 4 / 2 |
| Worker zero, same / new owner | 109 / 111 | 20 / 22 |
| Worker one, same / new owner | 201 / 203 | 33 / 35 |
| Direct one, same / new owner | 103 / 105 | 14 / 16 |

There are **22 selected CFG paths and 113 distinct explicit store sites**.
Counts include local writes and read/modify/write operations. They exclude
implicit PUSH/call-stack effects, imported effects and nested callee writes
from each individual caller's count. PUSH sites are recorded separately;
prefetches are not stores. Capturing an entire FDE does not close its other
paths, and an exact CFG walk does not by itself prove branch feasibility.

From the repository root with the recorded Python/native tools on PATH:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/refill.py --out work/context-refill-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/refill.py --out work/context-refill-optimized
```

The 58 files in each new export are compared byte for byte, including native
stdout/stderr. The caller's GNU/LLVM exports must also match the previous
fresh exports. The prior fresh collector is replayed separately (18 files).
There are **142 rejected negative/scope controls**, including code/extent,
import/data/store mutations, wrong path choices, invented runtime values and
an invented FDE for the bit-count interval. Whole-body hashes may reject code
corruption before a narrower anchor check does. Arithmetic corroboration
covers 262,468 bit-count values, 327,680 preparation-modulo cases, eight
explicit preparation boundaries and eight byte-shift cases. These are finite
scalar checks, not runtime fixtures or source-equivalence tests.

[refill-validation.json](refill-validation.json) retains final commands,
source/log hashes and verification results. Historical full-suite and TLS
failures remain in their earlier reports; neither suite is claimed green.
The stale generated README catalogue failure is retained without editing
generated files. No full-scope component gate is advanced.

Open behavior includes general multi-item loops, metadata misses, contention,
provider/head acquisition, grouped collection, optional fills, counter-negative
handlers, actual mutable-table initialization and allocator invariants. Import
symbols are bound by relocations; mutex/errno behavior is a contract premise.
The class stride and size table are separate reads, not assumed equal. Bounds,
valid storage, ABI/canary preservation, aliasing, CPU bit-scan semantics and
interference limits remain explicit. The transport field's preservation over
every helper/resume path, general allocation ownership, Rust equivalence and
whole-node equivalence remain unclosed. All 92 gates remain false.

No captured code execution/emulation, external action, Rust build, commit or
push occurred. New code and analysis are independently authored MIT work;
target bytes and referenced evidence retain their original terms.
