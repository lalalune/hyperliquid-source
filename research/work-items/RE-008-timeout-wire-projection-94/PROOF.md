# Conditional timeout serialization contract

Target: node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Coordinates below are linked ELF virtual addresses and half-open intervals.
This is a manual instruction/dataflow proof with mechanical byte, unwind,
instruction-partition and local graph checks. No captured instructions ran.

## Contract and premises

Let `P` be the payload pointer paired with tag 2. Define `u64(A)` as the
little-endian 64-bit word read at address A, and `V(x)` as:

| x | bytes |
| --- | --- |
| 0..250 | one byte x |
| 251..65535 | FB, then x in two little-endian bytes |
| 65536..4294967295 | FC, then x in four little-endian bytes |
| 4294967296..18446744073709551615 | FD, then x in eight little-endian bytes |

Let `N = u64(P+0x10)` and `Q = u64(P+0x8)`. The successful tag-2 serializer
produces this byte string:

```text
02
P[0x58:0x6c]                  20 bytes
V(u64(P+0x50))
V(u64(P+0x18))
V(u64(P+0x20))
V(u64(P+0x28))
P[0x30:0x50]                  32 bytes
V(N)
for i = 0 .. N-1, R = Q + 0x60*i:
    R[0:0x14]                 20 bytes
    V(u64(R+0x18))
    V(u64(R+0x20))
    V(u64(R+0x28))
    V(u64(R+0x30))
    V(u64(R+0x38))
    V(u64(R+0x40))
    V(u64(R+0x48))
    V(u64(R+0x50))
    R[0x58]                   one byte
```

The QC/timeout/signer/signature names below are inferred field roles, supported
by the existing admission and timeout-path packets. The formula itself uses
observed offsets and widths, independent of those labels. It concerns the
serializer output before prefix concatenation and hashing.

Premises: tag 2; readable live payload and N contiguous 0x60-byte rows;
`96*N <= 2^63-1`; accessible stack, vector metadata and allocated output;
nonwrapping pointer arithmetic; stable input values from measurement through
writing; disjoint input, output and stack storage; ordinary SysV callee-save
behavior; normal successful allocation; and no foreign/reentrant modification
of any live/escaped storage. The opaque clock calls in the wrapper must also
preserve that storage. These are real premises, not conclusions from a
successful static export. Panic/unwind, allocation failure, invalid lengths,
invalid tags, inaccessible pointers, races and termination are outside the
contract.

## Concrete caller and selected route

The verifier corridor `454aa10..454aa30` records `R12 = incoming RSI`.
At `454aae5..454aaf3` the stack pair is `{2,R12}`. An optional QC verification
call occurs at `454ab03`; under the preservation premises, the pair at
stack+30 is passed to `454c050` at `454ab30`. Immediately after the digest
call, the verifier reads the claimed signer at P+0x58 and makes a pointer to
P+0x70 (`454ab49`). These later reads are context, not part of the serializer.
The complete verifier's admission, membership and signature checks are not
reproved here.

The separate signing corridor `454b170..454b1a5` constructs `{2,incoming RSI}`
at stack+50 and passes it to the same root at `454b1a0`. It establishes a
signing-side caller for the same variant; the actual signing callee is outside
this packet.

In the root corridor `454c050..454c0b0`, the original pair pointer is saved at
stack+0; the timing wrapper `4b747d0` is called at `454c0ab` with RSI pointing
to that saved word and EDX=0. The preceding prefix allocation is assumed to
return normally. The full wrapper saves that indirection at stack+48, passes
its address and the zero mode to `471ce30` at `4b74800`, then copies the
successful Vec triple at `4b74855..4b74866`. Its clock calls are explicit
opaque callees. A non-8 status takes a different, empty-vector/error-cleanup
path and does not establish this successful contract.

Full `471ce30..471d083` dereferences RSI into R12 (`471ce41`). Zero EDX takes
`471ce46 ->471cec1`, passes R12 to `45873d0` at `471cec9`, and returns its
result. That dispatcher dereferences its RSI once into R14 (`45873f4`), then
reads the tag and payload pointer from the original pair. Thus the observed
extra indirections cancel; the writer receives P, not a pointer to a pointer.
Nonzero instrumentation/TLS routes remain outside the selected path.

The two signed-32 relative tables at `6f5e18` and `6f5e2c` select index 2's
size arm `458749b` and write arm `4587753`. The full dispatcher begins the
measurement at one byte, calls `4778a70` at `45874b1`, then allocates the
measured count. The write arm loads the u32 constant 2 at `209edc`, calls
the scalar tag writer `4aa9ae0` at `4587764`, gates on status 8, and calls
`4778820` at `4587785` with the original payload in RSI. Status 8 returns the
Vec triple at `45877ff..4587813`. The selected table entries, constant, call
encodings and surrounding complete FDE are bound in the collector.
There is no claim about arbitrary tag values or the other four variants.

## Outer writer and measurement

Complete writer `4778820..4778a62` saves P in R15 and serializer config in
R14. At `477883a` it adds 58 to the input pointer and calls the fixed-20 writer
at `4778846`. It then calls the u64 writer `4aa9f80` four times, with EDX=0,
loading P+0x50, +18, +20 and +28 in precisely that order. Sites are
`477886e`, `477888f`, `47788b1`, `47788d6`.

The fixed-32 call at `47788f9` receives P+0x30. At `477890d` the writer reads
N from P+0x10 and serializes N through `4aa9f80` at `477891e`. Every preceding
operation is gated on result status 8; failure transfers to result copying
and then return, bypassing the success store. The mechanical local graph
checks independently establish that these seven calls occur in order on
every path to the success store at `47789c7`. This does not prove any callee's
semantic behavior or exceptional return.

Complete sizer `4778a70..4778be2` adds 20 to the count, uses the same four
u64 loads and EDX=0 sizer calls (`4778aaf`, `4778acd`, `4778aef`, `4778b11`),
adds 32 through `4aa9e20` at `4778b2d`, then calls the vote-list sizer
`485b780` at `4778b48`. Its local success store likewise requires all six
calls in order. The scalar and fixed-count helpers check size overflow;
the valid-size argument below rules it out on the claimed domain.

## Vote rows and the nested signature projection

N=0 takes `4778935 ->47789c7`, without reading Q or any row. Otherwise the
writer loads Q at `477893b`, computes end Q+96*N using multiply-by-three
then shift-five, and visits rows in increasing address order.

At `4778959`, `4aa9e50` appends the first 20 bytes of R. The four 16-byte
loads at R+0x18, +28, +38, +48 are copied, without byte permutation, to a
64-byte stack temporary. Its final word is a pointer R+0x58, not a copied
64-bit signature value. This temporary is passed to full
`4df20d0..4df2242` at `47789ab`. After status 8 the row pointer advances
by 0x60 (`477896d` plus `47789bb`) until it equals the precomputed end.
The list sizer `485b780..485b818` independently measures V(N), then visits
the same count and 0x60-byte stride, calling `4c7e7a0` for each row.

Full row sizer `4c7e7a0..4c7e830` adds 20 and constructs the same temporary:
R+0x18..R+0x58 copied as 64 bytes, then a pointer R+0x58. It calls signature sizer
`4df2250..4df2392`. This agrees with the writer's input projection rather
than assuming an opaque signature is serialized as 65 raw bytes.

The full signature writer makes eight ordered calls to `4aa9f80`, each
with EDX=0: temporary offsets 0,8,10,18,20,28,30,38, in hex. Those loads
are native little-endian u64 values from the original row's 64 bytes.
At `4df21d7` it loads the pointer at temporary+40, reads one byte through it,
and appends precisely that byte at `4df21ed`. It increments Vec length by
one and returns status 8. The local graph establishes eight ordered scalar
calls and the final byte store before that success value. A callee failure
instead copies the error record. The buffer-growth branch is excluded by
exact capacity below.

The signature sizer loads the same eight words and calls `4aaa230` in the
same order, then checked-adds one byte at `4df2356`. It never dereferences
the recovery-byte pointer; its value has fixed width. Its graph has the
same ordered-call and nonvacuity checks. This proves a variable-width
integer projection of the nested signature memory. It does not name the
eight words as cryptographic coordinates or prove signature validity.

## Shared leaves, exact capacity and result boundary

The complete fixed-20 writer copies 16+4 bytes and increases length by 20;
the fixed-32 writer copies two 16-byte pieces and increases length by 32.
Neither inserts a length prefix. The complete u64 writer compares FB,
10000, then the high 32 bits; its markers and payload widths establish V.
Zero EDX bypasses the two-byte rotate and four/eight-byte byte swaps.
The matching sizer contributes 1/3/5/9. The constant 2 uses the tag writer's
single-byte arm. These shared scalar semantics are already present in the
bincode/QC research; they are included as dependency closure, not new recovery.

For l(x)=|V(x)| and the eight row words a[i,k], the measured size is:

```text
S = 1 + 20 + l(u64(P+0x50)) + l(u64(P+0x18)) + l(u64(P+0x20))
    + l(u64(P+0x28)) + 32 + l(N)
    + sum_i(20 + sum_k l(a[i,k]) + 1)
```

Each nested row therefore occupies 29..93 bytes; scalar inputs affect its
size even though its memory stride is 96 bytes. An empty QC gives S=58..90.
For all N, S<=98+93*N. On `N<=floor((2^63-1)/96)`, this is below 2^63-1,
so all partial positive sums fit. The dispatcher's exact successful allocation
is S. Inducting over the tag, fields and rows, before every append the remaining
capacity equals that append plus its suffix. Scalar marker and payload
subwrites also fit. Hence the grow helper `454f5d0` is not reached under
the stability/disjoint-memory premises; its behavior need not be invented.

The complete writer reads outer signer P+0x58..6c, not the signature beginning
at P+0x70. It reads QC vote rows and their signatures, but does not sort or
deduplicate them. The selected normal output excludes native vector capacity,
padding and the outer timeout signature. The contract concerns a successful
serialization path, not validity or reachability of all these values in
consensus.

## Mechanical assurance and remaining unknowns

The packet binds 15 complete FDE exports plus 4 bounded caller corridors,
6036 selected bytes / 1509 instruction rows. Both disassemblers agree on every
selected byte boundary. Whole-body hashes and raw FDE/CIE/index bindings are
retained for all 18 distinct owners, including the three clipped owners.
All calls/transfers in the selected ranges are inventoried; slot relocation
records are retained. Caller corridors have no whole-function CFG claim.
The four success-gate results concern only their stated local CFGs. Opaque
indirect error-cleanup dispatches in wrappers are inventoried, not resolved.

34 semantic-window byte-identity controls, dispatch-table/data corruption,
FDE-range corruption and real native branch mutations are controls for the
evidence checks. The graph controls disable whole-image and witness/body
equality guards, so a changed success path is rejected by graph properties.
These controls do not constitute an x86 semantics proof or runtime test.

The Keccak/prefix implementation, root behavior after the selected call,
signature creation/recovery, validator membership, canonical wire decoding,
unwinding/LSDA paths and full consensus state behavior remain outside scope.
There is no reconstructed Rust implementation, compiled-byte match, component
completion gate, captured execution or hosted-CI claim.
