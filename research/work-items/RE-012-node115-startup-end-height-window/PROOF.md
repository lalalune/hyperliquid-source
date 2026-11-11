# Conditional startup end-height sampling composition

This proof connects the complete result producer, reverse/forward consuming cursors, collector, and previously reconstructed parent. It establishes an ordinary-return value and cleanup-request relation under explicit valid-state and callback premises. It does not establish the opaque loader's filesystem behavior, ordering policy, or the effects of allocation and drop implementations.

Addresses are ELF virtual addresses in Linux x86-64 node #115, SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. Full extents are listed in [README.md](README.md). The parent and file-height helper retain their existing [2098](https://github.com/lalalune/hyperliquid-source/pull/2098) and [2578](https://github.com/lalalune/hyperliquid-source/pull/2578) credit. No source implementation or first-byte-coverage claim is made.

## Domain and observation

Let E be the structural in-order sequence of a finite valid tree. A leaf contributes its active entries. An internal node contributes child0, entry0, child1, and so on through child[count]. The selected native traversal performs no key or numerical-height comparison, so this is not a filename, chronology, or height ordering claim.

The admitted state has valid, nonoverlapping tree nodes; counts within the physical node capacity; correct parent pointers and parent-edge indices; children one height below their parent; a null root parent; and a remaining count equal to the number of unconsumed entries. All relevant pointer/size arithmetic and memory spans must be valid. Both cursors bracket the remaining interval and retain allocated frontier paths. Owned entry payloads, result buffers and error objects must have lifetimes and separation sufficient for the observed reads and cleanup requests.

An active entry's capacity word must not equal the reverse exhaustion sentinel `0x8000000000000000`; it must describe the admitted live payload span. The entry count and sentinel tests alone do not establish that property for arbitrary raw tree bytes.

All called helpers on the selected route return ordinarily and preserve unrelated live frame, tree, result and callback state. In particular, allocation must not change the original iterator, and an error result must remain valid after the selected entry payload is released. Successful allocations supply disjoint valid writable storage. These are semantic premises, not properties proved merely by resolving a call slot.

Let N = |E| and k = min(N, 5). The conditional relation is:

1. Call the credited file-height helper on E[N-1], E[N-2], ..., E[N-k], in that order.
2. Count each call as one attempt, including errors. Store all k result pairs in call order.
3. Drain the remaining entries from the structural front without a file-height call.
4. Return the parent success tag and unsigned maximum among the successful sampled values, or the parent's error route when none succeeded.

An earlier loader error bypasses this relation. The error payload and diagnostic construction remain opaque. Chosen entry identities or sample counts used to explain this relation are not claimed as a native result ABI.

## 1. Parent frame and result domain

`0x595b1a0..0x595b512` builds two lazy cursors over the same loader-supplied tree. Root presence supplies canonical cursor flags. A null root forces the shared remaining count to zero; otherwise the loader's count is used. At `0x595b2b9`, the parent writes 5 at iterator-frame +0x48. Shared remaining is at +0x40. The producer call is at `0x595b2d2`.

The parent's maximum scan accepts a result when the low byte of its tag is zero: `0x595b2fd`, `0x595b38d`, `0x595b394`, and `0x595b3c7`. The CMOVBE selections at `0x595b3a7`, `0x595b3b8`, and `0x595b3d6` perform unsigned maximum selection. There is no signed-height comparison or maximum over unexamined entries.

The cleanup loop instead tests the full qword tag at `0x595b40d`, then calls through the error payload at `0x595b41d` when nonzero. Those tests are not interchangeable over arbitrary raw words: tag 0x100 would pass the low-byte acceptance test yet enter the cleanup branch.

The actual credited file-height helper closes the required narrower domain. In its complete `0x595b520..0x595bc3a` body, loader error writes EAX=1 at `0x595b565`; other error routes join EAX=1 at `0x595b8ab`; successful completion writes EAX=0 at `0x595bbdb`. These converge through the common return corridor at `0x595b8b0`. EAX writes zero-extend the tag word. Therefore actual ordinary returns have canonical tag 0 or 1, and the parent's two tests agree on this domain. No arbitrary raw-result-pair interface is justified.

If the scan accepts nothing, `0x595b341` calls the opaque diagnostic builder and the parent returns tag 1. Otherwise it returns tag 0 and the selected u64 maximum. Error-object drops, vector release and constructed-path release are cleanup requests; their actual resource effects and rendered diagnostic text are not reconstructed here.

## 2. Capacity and materialization

`0x5accff0..0x5acd160` reads remaining and budget, selects their unsigned minimum, and computes capacity times 16. It contains generic high-bit/size guards. Under the parent budget of five, capacity is at most five and the requested result storage is at most 80 bytes, so integer-size overflow cannot occur. Zero capacity uses pointer 8 without an allocation call. Positive capacity requires the allocator's successful ordinary return.

The producer then copies the 80-byte original iterator frame and recomputes min(remaining, budget) from that copy. A larger second value takes the growth call at `0x5acd114`. Excluding this branch requires the stated preservation premise: the allocation call must not modify the original iterator. Under that premise both minima agree. The generic growth helper `0x5963a10` is not closed by this proof.

The collector call at `0x5acd0dc` receives the **original** iterator pointer, loaded from RBX at `0x5acd0d9`, together with the output descriptor. The local copied frame is not substituted as the collector's input. The descriptor gives the initialized-length address, starting index, and result buffer. The returned header contains capacity, buffer pointer and the collector's initialized length. Input frame, stack copies, output descriptor and buffer must satisfy the stated non-aliasing and preservation premises.

## 3. Attempt budget and complete result retention

`0x543dab0..0x543dc44` copies the iterator frame locally. It tests the budget before the first request at `0x543daf5` and after each stored result at `0x543db2e`. Reverse traversal is called at `0x543db40`. The NEG/JO pair at `0x543db4d..0x543db50` recognizes exactly the signed-min sentinel in the first output word.

For a real entry, `0x543db5c` decrements budget **before** `0x543db64` calls the file-height helper. The returned RAX/RDX pair is saved, the sampled entry payload receives a release request if its capacity is nonzero, and both result words are stored at `0x543db20/24`. The result index advances and the buffer stride is 16 bytes. There is no branch that refunds an attempt on error or omits an error result from the vector.

The initialized length is published at `0x543db88`. The ordinary drain then calls the forward cursor at `0x543db95` and `0x543dbc6`, stopping on a zero node pointer. For each remaining entry, its capacity and payload pointer are derived from the returned node/index, and a release request occurs when capacity is nonzero. No file-height call occurs in this drain corridor.

Distinct landing paths after the ordinary return boundary perform additional cleanup/unwind calls. Their byte identity is retained, but exception routing and unwind completion are outside this ordinary-return proof. An unwind does not establish a complete k-result output or rollback equivalence.

## 4. Reverse/forward structural invariant

The observed node layout has parent pointer +0, 24-byte entries at +8, parent-edge u16 at +0x110, active-count u16 at +0x112, and child pointers at +0x118. The physical entry capacity is eleven. Leaf and internal node release-size operands are respectively 0x118 and 0x178. This layout does not prove a source type or all states reachable from the opaque loader.

Write f for the number of entries consumed from the front and b for those consumed from the back. The invariant is:

`remaining = N - f - b`, with live structural interval E[f..N-b).

The cursor edges bound that interval. Exhausted off-frontier subtrees can have release requests issued, while the paths delimiting the remaining interval must remain valid. Correct count alone is insufficient without these ownership/frontier conditions.

### Reverse step

`0x5152d00..0x515313a` decrements nonzero shared remaining before traversal. A lazy back cursor descends child[count] to the rightmost leaf. An active cursor with edge zero ascends through parent pointers and parent-edge indices, issuing release requests for exhausted nodes until a predecessor exists. Selecting edge-1 either moves the leaf edge backward or prepares the rightmost leaf of child[edge-1] when the selected entry lies in an internal node. The selected 24-byte entry is then copied to output. Under the invariant, this is E[N-b-1].

An impossible ascent past a null parent while remaining is positive reaches a panic path; it is excluded by the valid-tree/exact-count premises, not silently converted to ordinary exhaustion.

### Forward step

`0x51ded00..0x51df0aa` also decrements nonzero remaining before traversal. A lazy front cursor descends child0. An exhausted index ascends through parent edges, issuing release requests until another internal entry exists. The cursor then prepares the leftmost path of the right child or advances the leaf index and returns the selected node/height/index triple. Under the invariant, the selected entry is E[f]. The collector, rather than this cursor, reads the selected payload and requests its release.

### Meeting and terminal cleanup

Cursor preparation occurs before the current entry is returned. The relevant ownership invariant is that boundary paths stay live until their exhausted-edge ascent or terminal cleanup. Merely yielding a node's last contained entry does not immediately issue that node's release request. Thus a prepared next cursor can still refer to an empty but live boundary path when the two ends meet; the shared zero-count guard prevents another ordinary entry yield beyond the meeting point. The leaf/internal selection and ascent cases preserve this invariant according to the structural child/entry decomposition.

Both zero-count branches use the front cursor, clear its live flag, descend its lazy left boundary if necessary, and request residual node release along the parent chain. Their output sentinels differ: reverse writes signed-min in the first word; forward writes a zero node pointer.

- If N<5, an extra reverse exhaustion call handles terminal cleanup and clears the front flag. The following forward-zero call sees that cleared flag and does not duplicate the requests.
- If N=5, the budget stops sampling before an extra reverse request. The forward-zero call performs terminal cleanup.
- If N>5, the forward drain consumes N-5 entries and its final zero-count call performs terminal cleanup.
- N=0 with null root requires no node cleanup. A valid non-null empty root is a separate state whose remaining boundary nodes still receive cleanup requests.

These are conditional request/ownership arguments, not proof of actual reclamation by opaque callees or a machine-checked lifetime theorem.

## 5. Manual consequences, not executed cases

These examples are deductions from the conditional relation, not test passes, a generated oracle, or evaluated native instructions:

| Supplied structural state / ordinary results | Consequence |
| --- | --- |
| N=0 | No file-height calls and no accepted result. Null root and non-null valid empty root differ in residual node cleanup. |
| N=3 | Three reverse-order calls, including any errors; a later reverse exhaustion check clears the front cursor before the empty forward drain. |
| N=5 | Exactly five calls. Budget stops the sampling loop before an extra reverse exhaustion request; the forward-zero path handles the residual boundary. |
| N=6 | Exactly five calls, then one remaining entry is drained without evaluation. |
| Six reverse entries; the first five return errors and only the sixth would succeed | No sampled success. The sixth helper call never happens, so its hypothetical success cannot rescue the window. |
| One sampled success with value0 and all other sampled results errors | Parent success with value0, distinct from no success. |
| Accepted values `0x8000000000000000` and `0x7fffffffffffffff` | Unsigned maximum is `0x8000000000000000`; interpreting them as signed reverses the order. |
| Accepted values `0xffffffffffffffff` and `0x8000000000000000` | Unsigned maximum is `0xffffffffffffffff`; both are valid raw u64 payloads on the stated result domain. |

The examples do not prove that any particular filesystem reaches these supplied results or that structural order agrees with their numeric values.

## 6. Consequences and limits

The producer's ordinary initialized length is k=min(N,5). Errors remain in that k-element vector and consume attempts. A sixth structural entry is never evaluated, even when all first five return errors. Successful zero is distinct from an empty/all-error sample. The parent compares successful payloads as u64, including high-bit values and ties.

The tree shape supplies only a structural order. No relation to filename order, numerical height order, newest persisted state, global maximum, or complete startup acceptance follows without additional loader/filesystem evidence. The input loader, per-file operation, count and command helpers remain conditional dependencies; [PR3190](https://github.com/lalalune/hyperliquid-source/pull/3190) and [PR3193](https://github.com/lalalune/hyperliquid-source/pull/3193) are prior neighboring work, not new implementation territory here.

Allocation failures, generic growth after input mutation, malformed trees/counts, aliased ownership, callback side effects, dynamic error-drop implementations, panic/abort and unwind completion remain outside the result theorem. All claimed static call/data/relocation bindings require their own records; an address resolution or raw LSDA/CFI match is not a helper-effect proof.

All native observations come from one authenticated capture. GNU instruction decoding and separate ELF/raw-byte checks do not constitute two independent decoding providers or organizational corroboration. No captured executable, instruction evaluator, emulator, source-native comparison, or full node run supports this packet. No acceptance gate or byte-equivalence counter is advanced.
