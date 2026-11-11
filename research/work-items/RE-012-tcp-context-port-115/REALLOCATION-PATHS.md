# RE-012: same-pointer, copy and cache-return paths at 0x6365660

- Component `transport`, task RE-012; owned files are this evidence directory.
- Sole target Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: how does the selected call at `0x63503e3 -> 0x6365660` retain
  or replace the old buffer, and what state changes accompany each result?
- Status: selected small-size paths, two predicate paths, disabled-hook
  paths and imported-copy binding are bounded. Whole allocator behavior
  and ownership remain incomplete.

One selected route returns the original pointer P. Another takes candidate
Q from a cache, calls **`memcpy(Q,P,min(U,S))`**, inserts P back into an
old-class cache, and returns Q. Here U is the old metadata size and S is
the new size-class word; the copy is not parameterized by the requested N
or a logical initialized length. A null candidate returns zero after cache
metadata writes. A same-pointer result can also follow a counter decrement.
Thus result identity alone does not establish absence of state changes.

## Exported evidence and limits

[reallocation.py](reallocation.py) authenticates the whole node and checks
[reallocation-spec.json](reallocation-spec.json). Original bytes, native
disassembly, FDE identities, commands, versions and path records are under
[reallocation/records.json](reallocation/records.json).

| Exported interval | Bytes / instructions | Extent claim |
| --- | ---: | --- |
| `0x6365660..0x63673d9` | 7,545 / 1,607 | Complete reallocation-helper FDE |
| `0x6363d50..0x6364270` | 1,312 / 289 | Complete decision-helper FDE |
| `0x63b7240..0x63b7399` | 345 / 91 | Complete new-candidate hook FDE |
| `0x63b73a0..0x63b74f1` | 337 / 87 | Complete old-pointer hook FDE |
| `0x63b7500..0x63b7689` | 393 / 103 | Complete same-pointer hook FDE |
| `0x6350210..0x63503e8` | 472 / 100 | Revalidated caller prefix, owner ends `0x6352f5e` |
| `0x63f0a60..0x63f0a70` | 16 / 3 | PLT window, not an asserted function/FDE |

Total exported context is **10,420 bytes / 2,280 instructions**. Complete
exports support byte review, not complete branch, behavior or reconstruction
coverage. Only the nine selected paths below have their write/call sequences
analyzed here. The caller exports match the previous allocator packet exactly.
The PLT entry and runtime-import boundary are distinct from a reconstructed
memcpy body. No byte normalization masks are used.

## Caller inputs and runtime premises

From [ALLOCATOR-PATHS.md](ALLOCATOR-PATHS.md), the selected entry receives:

```text
RDI=B       RSI=0       RDX=P       RCX=U       R8=N       R9=0
stack arguments: option byte D, cache K=B+0x358, descriptor H
```

B is the previously joined TLS-associated base, P the old pointer, and U
an old metadata-derived size word. This supplement selects D=0 and retains
the caller's descriptor byte `[H]=1`. N is the positive size passed by growth;
the selected caller already admitted N<=4096. This does not establish valid
ownership of B/P/K/H or actual table contents.

The helper reads the same `.bss` class tables at `0x67277c0` and `0x6727a00`
to obtain S. In the selected branch S is nonzero and at most 4096. The
general small branch initially admits S<=0x3800, but the complete selected
replacement route and the selected predicate routes below are narrower.

Every use of class tables, metadata pointers, cache slots and counters
requires valid initialized storage and stable values for this path. The
copy branch additionally assumes candidate Q and source P meet memcpy's
validity/non-overlap contract. Q!=P and independent ownership are not
checked by the machine instructions at the copy call.

## Decision helper: returning P is not a no-write operation

At `0x636573f`, the helper calls `0x6363d50` with
`(B,P,U,S,0,D)` and a seventh stack argument pointing to scratch RS+0x58,
where RS is the reallocation helper's post-prologue RSP. The scratch word
written by the decision helper is not consumed on these selected main paths.

The decision helper's chosen paths require B!=0, the first pointer-metadata
cache tag matching P, small size-table routes and an unchanged canary.
It derives a metadata-header pointer by sign-extending the cached word's
low 48 bits and clearing its low seven bits; valid dereference is a premise.
It reads a header word E and eventually writes
`QWORD[0x6727a00 + 8*((E>>20)&255)]` to the supplied scratch pointer.
This observes a bit extraction and table read, not a recovered header type.

Let C(x) be the byte table at `(x+7)>>3`, and V(x) the QWORD table at index
C(x), where all small-domain accesses are admitted and values stay stable.
The selected paths use S<=4096, U<=4096 and V(S)<=4096. In particular the
helper applies the class lookup again; **idempotence of V is not assumed**.

- If C(U)==C(V(S)), the selected path reaches the counter block and returns
  AL=0. At `0x6363eb0` it subtracts one from DWORD `[B+0x98]`; the selected
  continuation requires the resulting signed word to be nonnegative.
  A sufficient admitted counter domain is 1..0x7fffffff. Other machine-word
  values and signed-overflow cases are not assigned the same invariant.
  A negative result branches to another helper, excluded here.
- If those class bytes differ and U<S, the comparisons at
  `0x6363e7c..0x6363e8c` produce a nonzero AL and reach the return path
  without that counter decrement. Other class-difference relationships
  and large-size routes remain open.

These two paths make no calls. Each saves a canary and writes the scratch
QWORD; the AL=0 path additionally writes the counter. They contain 105 and
102 instructions respectively before RET. No direct payload store occurs.
The counter path also reads the `.bss` table at `0x65096c0` using E's low
12 bits; the purpose of that table is not inferred.

## Main results and their side effects

| Selected path | Calls before return | Result and direct state effects |
| --- | --- | --- |
| Same pointer | Decision helper; `0x63b7500` | Returns P; decision helper can change the counter and scratch |
| Replacement with cache return | Decision helper; `0x63b7240`; `0x63b73a0`; memcpy PLT | Updates new-cache cursor/count, copies min(U,S), inserts P into old-class cache, returns Q |
| Null replacement candidate | Decision helper only | Updates new-cache cursor/count, then returns 0; no copy or old-cache insertion on this path |
| Local zero-class result | None | Returns 0 before decision helper; only local saved-argument/canary stores |

The main path counts are 76, 133, 93 and 46 instructions before RET. These
counts omit callee instructions. The local zero-class path is an observed
branch of this function; it is **not** claimed reachable from the prior
selected caller with unchanged tables, because that caller already rejected
a zero size-class word.

On the same-pointer route, AL=0 at `0x636574d` enters `0x6365b88`. The code
retains P as the final result and invokes the same-pointer hook. With
`[H]=1`, its event-like integer argument is `(1 xor 1)=0`. The meaning of
that code is not otherwise assigned.

On the replacement routes, AL!=0 continues through the small-cache path.
For class byte k=C(S), it forms slot `K+24*k`, reads cursor L from slot+8,
reads candidate Q from `[L]`, and compares low16(L) against WORD slot+0x18.
The selected regular-slot branch writes cursor L+8 and, for D=0, increments
QWORD slot+0x10. **The null check on Q follows these writes.** A zero Q
therefore does not imply unchanged allocator metadata or rollback.

The nonzero candidate route calls two hooks, then reaches the copy:

```text
0x6365806  compare U with S, unsigned
0x636580f  choose min(U,S)
0x6365816  call 0x63f0a60 with (Q,P,min(U,S))
```

With `[H]=1`, the new/old hook arguments include integers 7 and 3 and a
pointer to H+8. Hook effects are bounded only on the disabled paths described
below. The imported copy contract requires source readability, destination
capacity, non-overlap and successful dynamic resolution. This static packet
does not execute memcpy or prove those invariants. It also makes no claim
that newly exposed bytes beyond the copy count are zeroed or initialized.

## Old pointer returned to cache, not a proved system free

After copying, the selected branch requires BYTE `[0x6713606]==0`, U<=4096
and old class j=C(U)<=35. It forms old slot A=K+24*j and reads cursor M
from A+8. If low16(M) differs from WORD A+0x1a, then:

```text
0x63658b3  QWORD[A+8] := M-8
0x63658b7  QWORD[M-8] := P
```

The function subsequently returns Q, subject to its canary check. There is
no further call on this branch. These instructions establish **cache insertion
of P**, not an operating-system free, a deallocation contract for every
allocation class, or proof that the slot storage cannot alias live data.
Cache-limit, larger-class, metadata-based and enabled-option paths are open.

The `memcpy` identity is tied to the PLT entry's indirect JMP at `0x63f0a60`,
GOT slot **`0x64ee180`**, and its unique `R_X86_64_JUMP_SLOT` relocation
to dynamic symbol **`memcpy`**. The remaining two instructions are the
entry's lazy-resolution sequence. Loader behavior and the imported function
implementation remain external contracts, not reconstructed helpers.

## Disabled hooks and exact conditional closure

The three small hook functions all read DWORD **`0x6712360`** in `.bss`.
If it is zero and the saved canary is unchanged, each returns without a
nested call and with only its local canary store, plus implicit stack pushes.
Each selected disabled path has 23 instructions before RET.

This closes their direct transitive writes only under that runtime guard.
The flag being in `.bss` is not evidence that it remains zero during execution.
Their enabled paths contain further TLS/global/callback behavior and are not
closed here. Neither the hook flag nor the class tables are populated with
invented runtime values in the records.

## Verification and remaining work

There are **16 unique explicit store sites across the nine selected paths**:
ten in the main function, three in its decision helper, and one local store
in each disabled hook. This is a selected-path union, not a lexical census
of all 7,545-byte main-function branches or all captured bodies. Implicit
stack writes, imported memcpy effects and excluded callees remain separate.

The collector uses explicit encoded-edge choices and verifies exact call
sequences. It does not evaluate CPU state or emulate the captured code.
Eight scalar boundary cases validate the unsigned min relation, including
zero, equal, unequal and maximum-word operands; they are not runtime fixtures.

From the repository root with the established native/Python environment:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/reallocation.py --out work/context-reallocation-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/reallocation.py --out work/context-reallocation-optimized
```

All **68 negative/scope controls** reject: 16 anchor-byte changes, 7 wrong
extents, 3 relocation/symbol changes, 3 selected-store changes, 9 changed
entry edges, 9 other excluded edges, 14 invented runtime-data values,
5 invalid copy-size inputs and 2 wrong captures. Full-body hashes can reject
corrupt instructions before narrower pins. No excluded-state reachability
or complete semantic equivalence is established by these controls.

Normal and optimized exports are byte-identical. The preceding allocator
collector is replayed unchanged; all 34 focused existing tests pass.
[reallocation-validation.json](reallocation-validation.json) records commands,
scope, source hashes and local log hashes. GNU/LLVM and Capstone agree over
the retained bytes without masks. Historical full-suite failures, the TLS
metadata-path failure and stale generated README catalogue failure remain
recorded; the whole suite is not claimed green.

Valid frames, cache storage, metadata, ABI, stable guards, non-aliasing and
absence of interference remain premises. This packet does not conclude that
all allocator writes miss the outer transport word. No captured execution,
Rust reconstruction, network action, independent-agent review, commit or push
occurred. All 92 full-scope acceptance gates remain false.

Next: join these return values to **`0x6350210` after `0x63503e3`**, including
its null branch and subsequent accounting writes, before attributing the
complete allocator chain's effects. Fresh fallback `0x6353a70`, enabled hooks,
large allocations and remaining formatter callbacks are separate open gaps.

Follow-up: [ACCOUNTING-RETURN.md](ACCOUNTING-RETURN.md) now records the selected
null/nonnull continuations, two counter updates, four threshold-helper leaves
and conditional `0xA5` tail fill. This answers the bounded next question under
explicit runtime/ABI premises; it does not close the other gaps above.

New analysis and code are independently authored MIT work. Original bytes
and referenced evidence retain their own rights.
