# RE-012: allocation result and grow-error join on node #115

- Component `transport`, task RE-012; only this evidence directory is owned.
- Sole target Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: how does `0x141e0e0` choose allocation calls and encode the result
  consumed by formatter growth at `0x141c980`?
- Status: six static result paths and their caller/error joins are bounded.
  Allocator ownership, payload preservation and diagnostic behavior remain open.

The wrapper writes a success tag of **0**, or an error tag of **1**. It
rejects requested sizes with bit 63 set before calling an allocator. That
error writes only result bytes **[0,16)**; result+16 remains unwritten.
Allocator-null errors instead write all 24 bytes. The grow caller installs
the new pointer/capacity only after the success result, but the wrapper does
not itself establish what happens to the old allocation inside its callees.

## Byte scope and reproduction

[allocation.py](allocation.py) authenticates the entire target, checks
[allocation-spec.json](allocation-spec.json), and retains raw GNU/LLVM and
Capstone exports in [allocation/records.json](allocation/records.json).
Addresses are linked ELF VAs, without an assumed runtime load bias.

| Complete FDE interval | Bytes / instructions | Role |
| --- | ---: | --- |
| `0x141e0e0..0x141e162` | 130 / 43 | Result-producing wrapper |
| `0x141c980..0x141c9f2` | 114 / 35 | Revalidated grow caller |
| `0x141e264..0x141e279` | 21 / 6 | Error dispatch by first payload word |
| `0x141e280..0x141e29d` | 29 / 6 | Zero-word diagnostic prefix |
| `0x141e251..0x141e264` | 19 / 6 | Nonzero-word allocation-error bridge |

Total capture: **313 bytes / 96 instructions**. These are exported context
sizes, not new reconstruction coverage. The grow body was already exported
in [FORMAT-OUTPUT.md](FORMAT-OUTPUT.md); both native exports match that
packet exactly. Its catalogue dependency attribution is not new source or
equivalence evidence for the wrapper analyzed here. No imported record,
generated catalogue or shared tool is changed.

## Inputs and all six result paths

Use analytical coordinates, not a recovered public Rust ABI:

```text
O = RDI       output storage, observed envelope 24 bytes
C = RSI       old capacity-like word
P = RDX       old buffer pointer
N = RCX       requested size
```

At `0x141e0f3..0x141e0f6`, testing N and taking JS rejects `N >= 2^63`
when N is viewed as an unsigned word. Otherwise N is retained in R14 and
C is tested only for zero. The wrapper does not validate C, P or their
relationship and does not pass the numeric old capacity to either allocator.

| Path | Conditions and calls | QWORD O+0 | QWORD O+8 | QWORD O+16 |
| --- | --- | ---: | --- | --- |
| Size high bit | N has bit 63 set; no call | 1 | 0 | **Unwritten** |
| Empty fresh | N=0 and C=0; no call | 0 | 1 | 0 |
| Fresh null | `0<N<2^63`, C=0; allocation returns 0 | 1 | 1 | N |
| Fresh nonnull | Same inputs, nonzero return Q | 0 | Q | N |
| Existing null | `N<2^63`, C!=0; allocation returns 0 | 1 | 1 | N |
| Existing nonnull | Same inputs, nonzero return Q | 0 | Q | N |

The fresh call is at `0x141e125`, through
**`0x64df480 -> 0x6355830`**, with RDI=N. The existing-buffer call is at
`0x141e106`, through **`0x64df588 -> 0x635a7a0`**, with RDI=P and RSI=N.
Both bindings are unique `R_X86_64_RELATIVE` relocations. Names such as
"fresh" and "existing" describe this routing; their complete allocation
contracts are not imported merely from familiar call shapes.

The C!=0 route does not special-case N=0: it still calls `0x635a7a0`.
It also does not check that P is nonnull or valid. These are real wrapper
boundaries, even though the selected grow caller always requests at least
eight bytes and a valid existing allocation is a required external premise.
The C=0, N=0 result uses pointer word 1 without calling or dereferencing it.

The indexed store at `0x141e150` resolves to O+8 on the size-rejection
path, where R14=0, and to O+16 on the other paths. The final store at
`0x141e154` writes the complete QWORD tag. There are four lexical explicit
store sites in this wrapper, all through O. No explicit old-buffer payload
store, memcpy, free, alignment check or zero-fill occurs in its own body.
Such effects may occur inside either allocator and are not excluded.

The collector follows the six manually selected encoded paths to RET,
checking exact calls, decisions and write masks. It does not evaluate CPU
state or execute captured code. Assigned values in the table follow the
pinned immediate/register-copy instructions; the external result Q remains
an input premise. Aliasing output storage with P or another live object
would invalidate a general noninterference conclusion.

## Join to the growth caller and size boundaries

The earlier append/grow join passes `(header, length, request)` to
`0x141c980`. Its local result storage is `G_RBP-0x28`; its call at
`0x141c9bd` supplies O, old capacity, old pointer and the computed new size
to this wrapper. It then compares **DWORD O+0 with 1** at `0x141c9c2`.
All six normal wrapper exits above write a full tag of exactly 0 or 1,
so the non-error branch is now tied to tag 0 for this call chain.

On that branch, `0x141c9cc` writes QWORD O+8 into header+8, followed by
`0x141c9d0` writing the requested capacity into header+0. It does not load
O+16 for the success installation and does not directly change header+16.
On both error prefixes there is no direct header write before error dispatch.
This does not prove an allocator failure leaves the old allocation untouched.

For admitted headers `0 <= length <= capacity <= 2^63-1`, the arithmetic is:

1. A fitting append needs no growth, including an exact fit or zero request.
2. Otherwise an unsigned carry in `length+request` takes the caller's error
   path before the wrapper call.
3. Without carry, the requested capacity is
   `max(8, 2*capacity, length+request)` in this admitted old-capacity domain.
4. The wrapper rejects that value if it exceeds `2^63-1`.

Consequently no unsigned-add carry is insufficient for admission. On a
growth route, old capacity **at least `2^62`** produces a doubled size with
bit 63 set and is rejected. Old capacity `2^62-1` can still pass this size
guard when the requested total also fits; actual allocation success remains
unknown. A large capacity that already fits the append does not enter this
growth check.

Fifteen scalar cases check empty/zero, 8/9 minimum growth, exact fit,
one-over, the signed-size boundary, the doubling boundary, unsigned-add
carry and a maximum-capacity fit. For example, `(capacity=8,length=8,
request=2^64-9)` reaches size rejection with total `2^64-1`, while increasing
request by one takes the caller's add-carry error first. These arithmetic
worksheets are not allocation attempts or runtime feasibility evidence.

## Error payloads and the unwritten word

On a wrapper error, the grow caller loads O+8 into RDI and O+16 into RSI at
`0x141c9e4..0x141c9e8`, then calls through `0x64df498 -> 0x141e264`.
Thus it does load an unwritten word on the size-high-bit path. That fact
is preserved; it does not justify inventing a fully initialized result.

At `0x141e268..0x141e26b`, the error dispatcher tests RDI alone:

- Zero selects the call at `0x141e26d` through `0x64df6b0 -> 0x141e280`.
  This helper overwrites RDI with a fixed data address and **ESI with 35**
  before calling through `0x64df6b8 -> 0x1680e80`. The loaded, unwritten
  O+16 value therefore is not forwarded as RSI to that first diagnostic
  dispatch. No claim is made about source-level initialization rules.
- Nonzero selects `0x141e273`, through `0x64df490 -> 0x141e251`. Its
  bridge swaps the incoming argument words before its call through
  `0x64df6a8`: the allocation-null result's `(1,N)` becomes `(N,1)`.
  The downstream failure handler remains unclosed.

The unsigned-add carry path sets EDI=0 and reaches the same zero-word
dispatch without calling the result wrapper at all.

The fixed diagnostic address is **`0x456d73`**. The inspected 35-byte data
window is `capacity overflowa formatting trait`; its first 17 bytes are
`capacity overflow`. The independently observed ESI argument is 35.
That argument is not established here as a byte count: consumed length
remains null in the record, and the inspected window is not claimed as
one string or the displayed message. In particular, its equality to
`2*17+1` alone is not a validated downstream encoding rule.

The three error/diagnostic FDEs end in call instructions and have no RET
in their captured intervals. Prefix analysis stops at those calls. It
does not prove panic, abort, unwind, non-returning behavior, or safe behavior
if a presumed terminal diagnostic call unexpectedly returns.

## Writes, validation and remaining work

Across these five bodies there are **six lexical explicit memory stores**:
four result stores and two grow-header stores. The three diagnostic prefixes
have none. Implicit pushes, call return-address stores and transitive writes
are excluded from this count.

The result lies in the grow caller's local stack. Its header input is the
retained formatter header at OS-0x1d0, from the prior stack join. The direct
header interval remains disjoint from `[OS+0x188,OS+0x18a)` under valid,
distinct, nonwrapping storage. The wrapper's observed result writes do not
close allocator aliases, TLS/global effects, old-buffer lifetime or payload
copy semantics, so the entire outer handoff is still conditional.

Reproduce with the existing Python/native environment into fresh directories:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/allocation.py --out work/context-allocation-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/allocation.py --out work/context-allocation-optimized
```

All **53 negative/scope controls** reject: nine anchor-byte changes, a
data-byte change, a wrong diagnostic-argument annotation, 16 changed or
duplicate relocations, five truncated FDEs, four store-census changes,
six altered result paths, six invalid growth inputs, three overlapping
output intervals and two wrong captures. Full-body hashes can reject corrupt
instructions before their narrower pins. These controls do not prove invalid
runtime states are unreachable.

Normal and optimized exports agree byte for byte; the preceding formatter
collector is replayed and compared with its retained outputs. All 34 focused
existing tests pass. [allocation-validation.json](allocation-validation.json)
records exact commands, outcomes, source hashes and local log hashes.
GNU/LLVM and Capstone agree over all captured bytes, with no byte masks.

The stale generated README catalogue failure remains; the earlier full
suite and TLS metadata-path failure are still recorded and are not claimed
green. All 92 full-scope gates remain false. No Rust implementation,
independent-agent review, captured execution/emulation, network action,
commit, push or hosted CI result is claimed.

The [allocator-path follow-up](ALLOCATOR-PATHS.md) now bounds two call-free
returns behind **`0x6355830`** and joins **`0x635a7a0`** to a selected core
prefix ending at `0x6365660`. Payload preservation and failure ownership
remain open there and in fresh fallback `0x6353a70`. Nested formatter
callbacks and parent `0x25f0250` remain separate gaps.

New analysis and code are independently authored MIT work. Original bytes
and referenced evidence retain their own rights.
