# RE-012: allocator entry paths, TLS writes and existing-buffer delegation

- Component `transport`, task RE-012; owned files are this evidence directory.
- Sole target Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: which writes and further calls occur behind the two allocator
  slots selected in [ALLOCATION-RESULT.md](ALLOCATION-RESULT.md)?
- Status: two call-free fresh-return paths, three fallback prefixes, one
  existing-buffer tail transfer and one core prefix are bounded. Allocation
  ownership and payload preservation remain unclosed.

The fresh entry `0x6355830` can return a pointer read from a TLS-associated
list after three or four metadata writes, without calling another function
or directly writing payload bytes. Its other selected paths transfer to
`0x6353a70`. For a nonnull old pointer and nonzero size, `0x635a7a0` instead
tail-transfers to `0x6350210(P,N,0,1)`. On the selected small-size core path,
the first nested call is **`0x6365660`**, with the old pointer, size metadata
and requested size. This identifies a narrower ownership boundary; it does
not establish what that callee copies or frees.

## Capture scope and existing work

[allocator.py](allocator.py) and [allocator-spec.json](allocator-spec.json)
authenticate the whole capture. Raw exports, command lines, versions,
encoded transfers, selected paths and worksheets are in
[allocator/records.json](allocator/records.json).

| Exported interval | Bytes / instructions | Extent claim |
| --- | ---: | --- |
| `0x141e0e0..0x141e162` | 130 / 43 | Complete FDE; prior allocation-result caller |
| `0x6355830..0x63558f2` | 194 / 37 | Complete fresh-entry FDE |
| `0x635a7a0..0x635a814` | 116 / 33 | Entry prefix of FDE ending `0x635c6c7` |
| `0x6350210..0x63503e8` | 472 / 100 | Entry prefix of FDE ending `0x6352f5e` |
| `0x63e8d90..0x63e9152` | 962 / 256 | Complete earlier table-writer FDE; partial semantic reuse |

Total exported context is **1,874 bytes / 469 instructions**. Full hashes
of the two larger owners authenticate omitted bytes, but those hashes do
not provide omitted-CFG, store or behavior coverage. Likewise the recorded
identities of `0x6353a70..0x635582b` and `0x6365660..0x63673d9` supply no
semantic closure or exported-byte credit. No new implementation or
binary-equivalence denominator is claimed.

The allocation wrapper's two native exports match the preceding packet.
For the existing [table-fill packet](../RE-001-node115-lu-tablefill/README.md),
this supplement revalidates its target, five raw exhibits (192 bytes), full
owner digest/decode, call-free body and shared table-address instructions.
It does not replay the older global caller census or descriptor construction,
and does not import the older test-success claim. Original records remain
unchanged; their record/manifest hashes are retained here.

## Runtime tables and the new consumer join

Both entries read addresses inside ELF **SHT_NOBITS `.bss`**:

| Address | Observed role | Required runtime information |
| --- | --- | --- |
| `0x67277c0` | Byte lookup, index `(N+7)>>3` for small sizes | Initialized bucket-to-index values |
| `0x6727a00` | QWORD lookup indexed by that byte or old-pointer metadata | Initialized per-index size words |
| `0x6713606` | Core-prefix branch flag | Selected value zero |
| `0x6511738` | Core-prefix option byte | Value forwarded to the next callee |

The static reader correctly rejects treating these regions as file-backed
bytes. The collector records **runtime values as unknown**, not as copied
file bytes or observed zeros. ELF zero-fill intent does not establish values
after initialization or at these calls.

Writer LEAs at `0x63e8f44` and `0x63e9062` bind the same two table addresses
previously described by the table-fill packet. That packet's unfiltered
232-word array is now tied to actual consumers: the fresh entry reads it
at `0x635586b`, and the selected core prefix reads it at `0x635031d` and
`0x635034b`. The byte table is the preceding lookup in both small-size routes.
This resolves a consumer lead left open in the writer packet; it does not
prove that initialization ran or recover the descriptor's actual values.

For `0 <= N <= 4096`, the bucket expression ranges over 0..512. The collector
checks all 4,097 scalar inputs: bucket 0 has one input (zero); each other
bucket has eight. The formatter's selected growth request is at least 8,
but this entry's own size guard also admits zero. No concrete size-class
values are invented from this arithmetic.

The fresh entry zero-extends a byte index, admitting 0..255 at the machine
level; it does not check it against the writer's 232 entries. The core's
old-pointer metadata produces a 16-bit index and also has no check against
232 in this prefix. Bounds and initialized-table invariants are therefore
separate premises, not properties proved by the consumers.

## Fresh entry: two returns and three fallback paths

Let F be the FS segment base and T be the word loaded from `FS:[0]`.
Do not silently assume T=F. Define:

```text
k = BYTE[0x67277c0 + ((N+7)>>3)]
S = QWORD[0x6727a00 + 8*k]
A = T - 0x10a8 + 24*k
L = QWORD[A+0x360]                 old list cursor
Q = QWORD[L]                      candidate returned pointer
U = QWORD[FS:-0xd70] + S           modulo 2^64
```

The guard at `0x635583b` sends unsigned N>4096 to the fallback. Otherwise
`0x6355877` sends `U >= QWORD[FS:-0xd68]` to the same fallback. No carry
check accompanies this addition. The static unsigned worksheet explicitly
shows that a wrapping sum can satisfy the less-than guard; valid accounting
requires additional runtime invariants. It is not evidence of a reachable
overflow in a live node.

After passing that guard, the entry reads L and Q **before** comparing the
low 16 bits of L with the boundary at A+0x370:

| Path | Additional branch conditions | Explicit writes before return/transfer |
| --- | --- | --- |
| Regular slot return | `low16(L) != WORD[A+0x370]` | QWORD A+0x360 := L+8; FS:-0xd70 := U; increment QWORD A+0x368 |
| Boundary-advance return | First comparison equal; `low16(L) != WORD[A+0x374]` | Same three writes, plus WORD A+0x370 := low16(L+8) |
| Large fallback | N>4096 | None before tail transfer |
| Budget fallback | Small size, unsigned budget comparison fails | None before tail transfer |
| Slot-limit fallback | Both low-16 comparisons equal | None before tail transfer, although L/Q have already been read |

Both returns set RAX=Q at `0x63558bb` and RET at `0x63558be`. They make
no calls, pushes, explicit payload stores, null checks or zero-fill writes.
The cursor and count arithmetic is ordinary machine-word arithmetic; the
counter increment is not a locked instruction. Valid list storage, arithmetic
invariants and absence of interference are required. Q's nonnullness, size,
alignment and independent ownership are not established by these paths.

All fallback paths reach the direct JMP at `0x63558c0 -> 0x6353a70`, retaining
N in RDI. Fallback ownership and writes are not analyzed here. The five paths
contain 26/30/3/13/24 instructions respectively before their RET/JMP endpoint.

For each possible byte k the collector records the symbolic T-relative
cursor/count/boundary/limit offsets. For k=0 they are -0xd48, -0xd40,
-0xd38 and -0xd34; each increases by 24 per index. They must remain separate
from the F-relative budget words unless the TLS self-pointer identity is
established. These coordinates alone do not establish valid object sizes
or disjointness from the outer tracked word.

## Existing-buffer entry and selected core prefix

At `0x635a7a0`, RDI=P and RSI=N from the allocation wrapper. For **P!=0,
N!=0 and an unchanged FS:0x28 canary**, the entry restores its six saved
registers and stack adjustment, sets EDX=0 and ECX=1, and jumps at
`0x635a80f` to `0x6350210`. There is no prior call, copy or free. The sole
explicit store is the local saved canary; six register pushes are accounted
for separately. The null-pointer, zero-size and canary-failure branches
leave this selected prefix and remain open.

For these EDX/ECX values, the core retains P/N, obtains T and a canary,
sets an alignment-like intermediate to zero, and forms B=T-0x10a8. The
selected path additionally requires:

- BYTE `FS:[-0xd78]` is zero and BYTE `[B]` is nonzero.
- The pointer-metadata cache tag matches: for
  `j=(P>>26)&0xf0`, QWORD `[B+0x1b0+j]` equals `P&0xffffffffc0000000`.
- N<=4096; the new size-table word S is nonzero and
  `S <= 0x7000000000000000`, as encoded by the unsigned comparison of S-1.
- BYTE `[0x6713606]` is zero. The other branch paths are not closed.

It looks up old metadata via the cached base plus `(P>>9)&0x1ffff8`, takes
that QWORD's high 16 bits as an index into `0x6727a00`, and retains the
resulting old-size word. This is observed dataflow, not proof of the pointer's
allocation identity or of valid metadata contents.

Before its first call at **`0x63503e3 -> 0x6365660`**, the selected prefix
has 96 instructions, eleven explicit stack stores, six register pushes and
three argument pushes. No explicit TLS, global, old-buffer or new-buffer
store occurs in this prefix. Its register arguments at that call are:

```text
RDI = B                RSI = 0          RDX = P
RCX = old-size word    R8  = N          R9  = 0
```

Let CS be the core's stack immediately after its main prologue. Immediately
before CALL, stack arguments are the zero-extended option byte from
`0x6511738`, B+0x358, and a pointer to CS+0xf0, in that order. The local
descriptor writes are BYTE 1 at CS+0xf0, P at +0xf8, N at +0x100 and
QWORD zeros at +0x108/+0x110. Intervening padding is not initialized by
these stores. The callee may write this descriptor or touch allocator state;
its behavior is not reconstructed here. Thus neither entry proves payload
preservation, freeing or failure ownership for the existing allocation.

## Verification and remaining boundaries

Across the complete fresh entry and the two exported prefixes there are
**19 lexical explicit memory-store sites**. The 7 fresh sites are split
between the two return paths, the existing prefix has 1, and the core prefix
has 11. Counts exclude implicit push/call stores and all omitted/transitive
behavior. The earlier wrapper and writer are excluded from this new census.

From the repository root, with the established Python/native tools on PATH:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/allocator.py --out work/context-allocator-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/allocator.py --out work/context-allocator-optimized
```

All **67 negative/scope controls** reject: 12 anchor-byte mutations,
4 changed/duplicate relocations, 5 truncated owner extents, 2 omitted-owner
byte mutations, 2 attempts to label prefixes complete, 4 store-census changes,
8 invented-BSS/file-read cases, 5 changed fresh paths, 13 excluded prefix
edges, 4 invalid bucket inputs, 3 invalid class inputs, 3 invalid counter
inputs and 2 wrong captures. The full owner hash can reject mutations before
individual instruction checks. These controls do not prove excluded runtime
states unreachable or establish source behavior equivalence.

Normal and optimized outputs match byte for byte. The prior allocation
collector is replayed unchanged. All 34 focused existing tests pass;
exact commands and log hashes are in
[allocator-validation.json](allocator-validation.json). GNU/LLVM and Capstone
cover the exported bytes without masks. The historical full-suite failures,
TLS metadata-path failure and stale generated README catalogue failure remain
recorded; no whole-suite success is claimed.

No captured execution/emulation, Rust implementation, network action,
commit, push or independent-agent review occurred. All 92 full-scope gates
remain false. This work narrows the allocator boundaries while retaining
unresolved table initialization, TLS identity, pointer validity, aliasing,
concurrency and allocation ownership premises.

The [reallocation-path follow-up](REALLOCATION-PATHS.md) now bounds selected
same-pointer, copy and old-pointer cache-insertion paths at **`0x6365660`**.
It preserves metadata changes on failure and leaves the caller's later
accounting open. Fresh fallback `0x6353a70`, table descriptor construction
and remaining formatter callbacks stay separate unresolved questions.

New analysis and code are independently authored MIT work. Original bytes
and referenced evidence retain their own rights.
