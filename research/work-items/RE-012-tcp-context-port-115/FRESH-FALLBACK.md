# RE-012: fresh small-size fallback on node #115

- Sole target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Task/component: RE-012 transport-context helper effects, with RE-001
  address/data bindings. Only this existing evidence directory is changed.
- Bounded question: what are the initial guards, cache-return writes and
  next call boundaries behind fresh fallback `0x6353a70`?
- Status: selected static observations. No Rust implementation, captured
  execution/emulation, independent-agent review or acceptance gate.

The fresh fallback can return a cached pointer after cursor/count and
accounting writes. Unlike the earlier fast entry, these selected slow
routes test the cached pointer for null. A null result writes the integer
error code **12** through the `__errno_location` import and returns zero,
but its cache mutations have already happened. A separate out-of-range
class-index branch reaches that error return without the cache mutations.

The two slot-boundary comparisons also identify where cache returns stop
and the next helpers become necessary. This packet records those call
arguments; it does not attribute unexamined refill-callee effects to the
selected cached returns.

## Captures and prior evidence

[fresh.py](fresh.py) authenticates the complete target before interpreting
[fresh-spec.json](fresh-spec.json). It binds exact FDE extents, full body
hashes, instruction anchors, selected stores, RIP-relative operands,
call targets, ELF data sections and the errno import. Raw evidence is in
[fresh/records.json](fresh/records.json), with [commands](fresh/commands.json)
and [versions](fresh/versions.json). GNU/LLVM raw stdout/stderr and Capstone
exports are retained without byte masks.

| Export | Virtual interval, end exclusive | Bytes / instructions |
| --- | --- | ---: |
| [Fresh fallback](fresh/fresh_fallback.capstone.txt) | `0x6353a70..0x635582b`, complete FDE | 7,611 / 1,691 |
| [Fast entry](fresh/fast_entry.capstone.txt) | `0x6355830..0x63558f2`, complete FDE, prior evidence replay | 194 / 37 |
| [Errno PLT](fresh/errno_plt.capstone.txt) | `0x63f0ad0..0x63f0ae0`, PLT window | 16 / 3 |

Total: **7,821 captured bytes / 1,731 instructions**. A full export does not
mean all branches are understood and is not an implementation comparison
denominator. These text/PLT file offsets are `VA-0x1000`, checked against
actual ELF sections. FDE identity supplies the stated extent, not a claim
that unwind records enumerate every function in the node.

[ALLOCATOR-PATHS.md](ALLOCATOR-PATHS.md) previously pinned this fallback's
identity and its incoming `0x63558c0` tail jump, while leaving its semantics
open. Both regenerated fast-entry native exports match that packet exactly.
The focused seed-candidate search supplies no additional boundary proof.
The two mode-one leaves from [ACCOUNTING-RETURN.md](ACCOUNTING-RETURN.md)
are revalidated against the target and joined below under their existing
premises. They are reused evidence, not newly discovered helper paths.

## Entry guards and cache fields

Define `N=RDI`, `F=FS base`, `T=QWORD[FS:0]`, and `B=T-0x10a8`. Define `SS`
as this function's RSP after its prologue. The prologue saves six registers
with PUSH and explicitly saves the FS:0x28 canary at `SS+0x88`.

The selected small-size routes require `BYTE[F-0xd78]=0` and unsigned
`N<=4096`. If the byte is nonzero, the exported prefix instead stops before
`0x6353d55 -> 0x63ef8e0(B,0)`; no TLS-transition semantics are credited.
Larger-size branches also remain outside the selected return paths.

At `0x6353ad6`, the byte class index is
`k=BYTE[0x67277c0+((N+7)>>3)]`. The addition cannot wrap for this small domain.
The comparison at `0x6353adb` rejects **k>231** before loading a size word.
Otherwise, `S=QWORD[0x6727a00+8*k]` is retained in R13. Both tables are `.bss`;
their runtime contents remain unknown. No size, alignment or monotonicity
invariant is derived from their addresses or ELF zero-fill intent.

For the selected cache route, `BYTE[0x6713606]=0`. The extra unsigned test
`N>0x3800` at `0x6353b11` is necessarily false under `N<=4096`. Let:

```text
A = B + 24*k
L = QWORD[A+0x360]
Q = QWORD[L]
b = WORD[A+0x370]
e = WORD[A+0x374]
```

The loads of `L` and `Q` happen **before** either boundary comparison. Valid
readable slot/list storage is therefore a premise even on a refill route.

| Selected route | Condition | Cache writes before testing Q |
| --- | --- | --- |
| Regular | `low16(L) != b` | QWORD `[A+0x360]=L+8` at `0x6353b46`; QWORD `[A+0x368]++` at `0x6353b4d` |
| Boundary advance | `low16(L)==b`, `low16(L)!=e` | QWORD `[A+0x360]=L+8` at `0x635412a`; WORD `[A+0x370]=low16(L+8)` at `0x6354131`; same count increment |
| Both bounds equal | `low16(L)==b==e` | No cache cursor/count write before the selected first refill call |

These are low-16-bit comparisons, not full-pointer equality checks. The
cursor addition and count increment wrap at machine-word width; they are
not locked instructions. No ownership or usable-allocation guarantee for
`Q` follows from reading it out of this list.

## Null and invalid-index results

The null test at `0x6353b55` follows the cache writes. A null cached `Q`
branches to `0x6353d3c`, whose CALL targets PLT `0x63f0ad0`. The PLT jumps
through `0x64ee1b8`. The unique JUMP_SLOT record has `r_info=85899345927`,
symbol index 20, addend zero, and symbol **`__errno_location`**.

On a normal imported return, `0x6353d41` clears R12D and `0x6353d44` stores
DWORD `12` through the returned RAX pointer. An unchanged canary then leads
to `RAX=R12=0` and RET. The import's ordinary pointer/ABI contract remains
a premise; its libc implementation is not executed or reconstructed.

The `k>231` branch uses this same error path. Its only explicit stores are
the local canary and imported error word. Cache-null paths additionally
retain two cache writes (regular) or three (boundary advance). Neither
error path performs the nonnull accounting update below. The initial
fast-entry work, if any, is separate from this local slow-function census.

## Nonnull accounting and return

For `Q!=0`, the function constructs a descriptor at `H=SS+0x40`:

| Offset | Written value |
| --- | --- |
| BYTE `H+0` | `1` |
| QWORD `H+8` | `&B[0x338]` |
| QWORD `H+0x10` | `&B[8]` |
| QWORD `H+0x18` | `&B[0x10]` |
| QWORD `H+0x20` | `&B[0x340]` |

Padding `H+1..H+7` is not written by this construction. If `oldC` is the
counter value read at `0x6353b5e`, the store at `0x6353ba0` is
`[B+0x338]=(oldC+S) mod 2^64`. The subsequent unsigned condition is:

```text
S >= (QWORD[B+0x10] - oldC) mod 2^64
```

If true, `0x6353f88` calls `0x63eec80(B,H)`; equality calls the helper too.
The descriptor matches the previous packet's first, mode-one accounting
descriptor. Its two call-free leaves can therefore be joined under the
previous guard/countdown/storage premises. In particular, connecting the
FS-relative entry flag to `BYTE[B+0x330]=0` requires `F=T` and preserved state.
The helper may update `[B+8]`, countdowns, `[B+0x10]`, both auxiliary words,
and its local atomic stack location. These callee writes are additional to
the direct caller census.

On normal helper returns and stable canary, the function returns retained
`Q` from R12. The selected cache-return instructions themselves contain no
direct payload store, memset or fill call. This is a conditional destination
claim with non-aliasing premises, not an assertion that allocator metadata
cannot alias the outer transport context or that every fresh route leaves
payload bytes untouched.

## Joining the actual incoming fallback conditions

The prior fast entry's **budget** and **slot-limit** paths both tail-jump
through `0x63558c0`, preserve `N`, and make no stores before that jump.
They are not interchangeable explanations of a slow cache return.

Under the selected slow guards and stable class/list data, a fast
slot-limit fallback has already observed `low16(L)==b==e`. The slow function
rereads those same fields, so it proceeds to its both-bounds-equal handling.
It cannot be joined to a regular or boundary-advance cached return without
an intervening change to those observations. The separate fast large-size
fallback also cannot enter the selected `N<=4096` path with unchanged `N`.

For a budget fallback, assuming `F=T` and stable values, the fast test is:

```text
((oldC + S) mod 2^64) >= QWORD[B+0x340]
```

The slow accounting-call test uses `[B+0x10]` and wrapped subtraction instead.
The auxiliary word need not equal that threshold, and wrap cases differ.
For example, `oldC=8,S=8,auxiliary=16,threshold=24` takes the fast fallback
but skips the later accounting call. These are scalar counterexamples, not
captured runtime fixtures. Thus the two recorded slow outcomes remain
conditional; a fast fallback alone does not prove the helper is called.

## Selected first refill boundaries

For both bounds equal, the selected prefixes further require:

- Signed `BYTE[B+1]<=0` at `0x6354141`; this includes byte values 128..255,
  not just zero. Positive signed values branch elsewhere.
- `E=QWORD[B+0x90]` is nonnull; otherwise provider acquisition is unclosed.
- Unsigned `DWORD[0x64ffb80]<=2`. Its `.data` file initializer is 2, but that
  does not establish its value at the call.
- `W=QWORD[0x6728868]` denotes valid readable table storage. The pointer
  cell is `.bss` and its runtime value/initialization remain unknown.

The word at `W+2*k` then selects these first-call interfaces:

| Word | Call site / target | Register arguments | Direct stores before call |
| --- | --- | --- | --- |
| Nonzero | `0x63541d1 -> 0x63e9cd0` | RDI=B; RSI=B+0x358; RDX=&A[0x360]; ECX=k; R8D=1 | Local canary and saved `B+0x358` at SS |
| Zero | `0x6354cda -> 0x6364880` | RDI=B; RSI=E; RDX=N; ECX=k; R8D=0 | Local canary only |

Each prefix stops **before** its call. In the nonzero branch, a subsequent
encoded call to `0x63e9c40` also exists at `0x63541eb`; its result and
post-call scratch-byte test are not included in a completed refill claim.
The already-read old `Q` is replaced by provider/callee state along these
routes and is not credited as the returned allocation.

Exact FDE extent/hash identities for `0x63ef8e0`, `0x63e9cd0`, `0x63e9c40`
and `0x6364880` are recorded as **semantics_closed=false**. Hashing their
bytes does not count as analyzing their bodies or closing side effects.

## Verification and remaining work

The evidence contains **12 selected paths**: seven slow returns, three
prefixes stopping before unclosed calls, and two revalidated incoming fast
prefixes. The prior mode-one helper leaves are reported separately.

| Slow selected path | Instructions before endpoint | Direct explicit stores |
| --- | ---: | ---: |
| Regular nonnull, below threshold / helper called | 73 / 77 | 9 / 9 |
| Boundary nonnull, below threshold / helper called | 77 / 81 | 10 / 10 |
| Regular / boundary null | 61 / 65 | 4 / 5 |
| Invalid class index | 39 | 2 |
| TLS-transition call prefix | 18 | 1 |
| Refill nonzero / zero table-word prefix | 64 / 62 | 2 / 1 |

The selected union has **13 explicit store sites**, all in the slow
function. It excludes six prologue PUSH writes, implicit call-stack effects,
imported effects and helper writes. This is not an all-path store census.

From the repository root with the established Python/native environment:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/fresh.py --out work/context-fresh-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/fresh.py --out work/context-fresh-optimized
```

All **66 negative/scope controls** reject: 14 code-anchor changes, three
wrong extents, three relocation/import changes, three store changes,
12 changed entry edges, ten excluded edges, eight invented runtime values,
two changed initial-data bindings, four invented callee-closure claims,
five invalid scalar inputs and two wrong captures. Full-body hashes may
reject corrupted code before narrower pins. Eight scalar threshold cases
exercise equality, distinct thresholds and wrap; they are arithmetic
corroboration, not target execution or source-equivalence tests.

Normal and optimized exports match byte for byte. All 23 previous accounting
exports replay unchanged. The 34 focused existing tests pass; reproduction
passes. [fresh-validation.json](fresh-validation.json) retains commands,
source hashes and local raw-log hashes. The generated README catalogue
remains stale; historical full-suite and TLS failures remain recorded.
The full suite is not claimed green, and no generated file is edited.

Runtime tables, valid storage, TLS identity, ABI, aliasing, no interference,
error-import behavior and the previous accounting-helper premises remain
explicit limits. Large sizes, nonzero state/global guards, provider creation,
refill effects and complete allocation ownership remain open. All 92
full-scope gates remain false. No captured execution, external/network action,
Rust build, commit or push occurred.

Next bounded question: analyze **`0x63e9cd0`** at the nonzero-table refill
boundary, especially which slot/cursor fields it changes before the following
`0x63e9c40` call. Keep the zero-table alternative `0x6364880` separate until
its behavior is established against this same target.

The subsequent [refill-chain supplement](REFILL-CHAIN.md) addresses this
question for selected zero/one-item paths, follows both helper interfaces to
the original caller, and separates their cache/bitmap/count effects. It also
records the metadata and marker callees and the directly called bit-count
interval. General refill and allocation ownership remain open; this earlier
prefix-only evidence is retained without inflating its original scope.

New analysis and code are independently authored MIT work. Original bytes
and referenced evidence retain their own rights.
