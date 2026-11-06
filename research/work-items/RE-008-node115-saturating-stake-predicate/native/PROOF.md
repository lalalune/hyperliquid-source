# Independent static proof of the flat-map predicate

Read with `CONTRACT.md`; every theorem below is conditional on its stable-memory, topology, count, ordinary-import and frame premises. This is a manual source-recovery proof over authenticated instruction bytes, not execution, emulation, formal machine verification, or a claim about original constructors. No library, reference model or corpus was used to derive it.

## 1. Evidence and closure

The five complete FDEs are 2,542 bytes / 643 rows. The original private `native-admission.json` records PT_LOAD mappings, raw body hashes and CIE/FDE bytes; `native-bindings.json` adds the complete call census, import/RELATIVE bindings and data records. Full texts are retained in this directory. GNU decode is evidence to be read alongside exact bytes, not an execution oracle. Every retained instruction row covers the complete body contiguously and agrees with the authenticated ELF bytes.

The ordinary admitted call graph is:

```
4d3e1a0 predicate
  4e44c00 selected fold
    5138730 key next
    57f54e0 flat lookup
      memcmp(physical key, query, 20)
  4e406f0 all fold, tag 2 only
```

Direct call edges are encoded at `4d3e217 -> 4e44c00`, `4d3e2df -> 4e406f0`, `4e44c48/4e44c80/4e44ca5 -> 5138730` and `4e44da6 -> 57f54e0`. Flat lookup calls imported memcmp at `57f5522`, `57f55bf`, `57f55e6`, `57f564f`, `57f567a`. The register call at `57f55bf` uses RBP loaded from the same import slot at `57f5591`; no intervening instruction writes RBP and each import must preserve callee-saved RBP. All five request exactly twenty bytes.

Five additional calls occur only in excluded branches: selected-fold tree-map memcmp at `4e44d21`, all-fold tree failures at `4e40976/4e40985`, and key-iterator malformed-state failures at `513892f/513893e`. The total census is therefore 16 syntactic sites. This is not a fixed runtime call count.

`0x64dfb50` is the undefined `memcmp` symbol's GLOB_DAT slot (type 6, symbol 12, addend 0). Slot `0x64df830` is a symbol-zero RELATIVE entry to `0x1680c10`. The two passed Location records at `649cd70` and `649cd58` have RELATIVE string pointers to `44ae86`, the 38-byte `node/src/consensus/validator_stakes.rs` literal, with line/column metadata 30:15 and 26:15. Source locations associate the operation with a source file; they do not recover a function/type signature or make a logging/overflow call appear. No normal flat route calls an overflow hook.

## 2. K initialization and private state

At `4d3e1af..4d3e1c7`, the predicate reads root r and height H, sets a tag to 1 iff r is nonzero, and chooses remaining N as zero for a null root or K+16 otherwise. The 88-byte descriptor at predicate stack+16 has:

| Relative field | Initial value |
| --- | --- |
| +0 | root-nonnull tag (0 or 1) |
| +8 | front node = 0 |
| +16 | root r |
| +24 | height H |
| +32, +40, +48, +56 | corresponding unused back-cursor tag / zero / root / height |
| +64 | remaining N |
| +72 | M pointer |
| +80 | pointer to a saved K pointer |

The selected fold copies all 88 bytes to its own stack+32 at `4e44c0e..4e44c3e`. The key helper receives that copied descriptor. It writes only offsets +0, +8, +16, +24, +64; its frame and these fields do not overlap the saved M at +72. Back-cursor fields and the final K-pointer field are not dereferenced by these five functions. Thus native iteration consumes a local cursor, not the original K.

For N=0, `5138731..5138738 -> 5138773` returns null before tag, node, height, key, or parent dereferences. This proves both null-root and nonnull-root/zero-count inert cases without presuming an original source constructor.

## 3. Complete in-order sequence from a valid key tree

Define I(v) recursively as in CONTRACT: for height zero, the node's keys in slot order; otherwise I(child0), key0, I(child1), ..., key(k-1), I(childk). This definition concerns topology/slot order only. No key-byte comparison or uniqueness occurs.

### Initialization

On the first nonempty call, `513873a..513873d` decrements N, and the initialized tag passes the exact dword-equals-1 check at `5138741`. Front node is zero, so `5138777..5138811` descends child zero from root H times, then stores that leftmost leaf as front node and sets front height/cursor to zero. The descent splits H into remainder H mod 8 and a multiple of eight. The remainder loop at `51387a0` performs exactly one child-zero load per iteration; the unrolled loop `51387c0..51387f1` performs eight. The subtraction by eight and unsigned multiple-of-eight loop are exact. H=0 skips descent. Finite height-consistent child spans therefore reach the leftmost leaf, without inventing a helper result.

The temporary initialization field used to zero height/cursor points to descriptor+16; it is not an input-node write. Tag is set to one and front-node stored at `51387fe..513880c`.

### Persistent frontier invariant

Before each subsequent nonempty call, the descriptor front is a leaf L, height zero, and an index i between zero and L.k inclusive. All keys strictly preceding this frontier in the complete in-order expansion have already been returned. The remaining field is the number of unreturned keys. The next call begins by decrementing a positive count, reserving exactly one next return. On the first call the initialization establishes the same frontier before selection.

If i<L.k, `513875b..513876b` selects L and i. Since its depth from the frontier is zero, `5138892..5138899` prepares frontier (L,i+1). `51388f1..51388f9` computes L+8+20*i and returns that key. This is exactly the next I(L) element.

If i>=L.k, valid frontier means i=L.k. At `5138830..5138850`, ascend to the parent, increment a local depth d, and read the exhausted child's recorded parent-edge index j. Topology gives `0<=j<=parent.k`:

* j=parent.k means the last child is exhausted; that entire parent subtree is exhausted, so repeat ascent.
* j<parent.k means the next in-order item is the parent's key j, immediately following the exhausted child subtree. Select that parent and j.

No byte comparison, ordering or uniqueness premise is used. Empty leaves and zero-key internal nodes are covered: the same ascent skips their exhausted expansion. An empty internal node has only child zero, so j=0=parent.k correctly ascends again. There is no minimum occupancy assumption.

The ascent cannot reach a null parent on a nonempty call. Such a reach would mean the complete root expansion was already exhausted, contradicting the exact positive remaining count at entry. Thus the `5138928` failure route is unreachable under the invariant, rather than assumed to return harmlessly. Depth cannot exceed H, so its increments do not overflow the admitted bound.

### Internal-key return and right-subtree preparation

After ascending d>0 edges to a selected parent key j, the next frontier must be the leftmost leaf of that parent's child j+1. At `5138857..5138862`, the initial child-pointer address is `parent+0xf0+8*j = parent+0xe8+8*(j+1)`. The descent then makes exactly d pointer loads: the first selects child j+1; each remaining load selects child zero of the newly reached internal node. Because the selected parent has height d, this reaches a leaf. The remainder loop `5138870..5138880` handles d mod 8, and `51388b0..51388dd` makes exactly eight loads per unrolled iteration. Both cases leave the next front index zero.

Crucially, the key returned now is still from the selected parent: RDX retains the parent and RAX its key index while RCX becomes the new leaf. `51388f1..51388f9` forms `parent+8+20*j`; `5138904..5138910` stores the new leaf/zero height/front index. Preparing a right subtree does not return its first key prematurely or omit the parent key.

### Exhaustion and totality

Every positive-count call returns exactly one next key and decrements remaining once; no normal path returns null after that decrement. It leaves the frontier immediately after the returned item. By induction, N such calls yield exactly Q=I(root), with multiplicity and order intact. The following call sees remaining zero and returns null without attempting another ascent, so exhausting the last leaf never requires a spurious root-parent access. Every descent/ascent is bounded by finite H and every outer call consumes a count, establishing ordinary termination under readable topology. The tag failure at `5138937` is impossible because initialized nonempty tag is 1 and helper writes preserve 1.

This is a tree-to-value-sequence theorem, not proof that the source type is BTreeSet, that original constructors allow duplicate or unsorted keys, or that a safe sequence API validates native topology. Source correspondence explicitly requires its supplied complete Q to equal this expansion. It must not silently deduplicate it.

## 4. Flat lookup: a finite order-statistic proof

For n=0, `57f54eb..57f54f6 -> 57f5561` sets both indices zero; it eventually returns EAX=1/RDX=0 without any row read. Capacity/head are not loaded on this route. The data word is loaded to form an unused base address. This justifies the native inert empty contract, including the distinction from the safe canonical-head policy.

For n>0 with canonical h<c, normalization at `57f5501..57f5508` leaves h unchanged. Set f=c-h. `57f550b..57f5514` computes n-f and branches on unsigned below-or-equal:

* If n<=f, the later code replaces the temporary underflowed remainder and constructs one segment at d+32*h of length n. It does not consume the wrapped subtraction as an index.
* If n>f, first segment length is f and second length b=n-f>0. Since n<=c, both lengths fit within the backing rows.

### Contiguous segment selection

Both native binary loops have the same mathematical recurrence. Let A be a nondecreasing segment of length L>0 and q the query. Initialize base i=0, width m=L. While m>1, set t=floor(m/2), j=i+t; compare A[j] with q. If A[j]>q, keep i; otherwise replace i by j. In both cases replace m by m-t. These are the instructions `57f55a0..57f55d2` for the first/contiguous segment and `57f5630..57f5666` for the wrapped second segment.

To prove the recurrence without using the machine loop as an oracle, define the order statistic

`r = max({j in [0,L): A[j] <= q} union {0})`.

The invariant is `0 <= i <= r < i+m <= L`. Initially it holds. If A[j]<=q, sortedness gives j<=r, so moving i to j and reducing width by t preserves the upper endpoint and invariant. If A[j]>q, sortedness gives r<j (j>0 and the empty-set convention r=0 also satisfies this); keeping i while using m-t>=t preserves containment. Width strictly decreases while m>1. At termination m=1 forces i=r.

The final comparison therefore has three meanings:

* A[r]=q: r is the last equal key in the segment, since it is the last <=q.
* A[r]<q: insertion is r+1, the number of segment keys <q.
* A[r]>q: no segment key is <=q, r=0, insertion is zero.

`57f55ec..57f5608` and `57f5680..57f5696` encode exactly those equal/status/index outcomes: a nonzero compare yields status 1 and adds the comparison's sign bit to r; equality gives status 0. All candidate and final indices remain in [0,L), and the miss insertion in [0,L]. The proof makes no assumption that equal keys carry equal weights.

### Two segments and the seam exception

On a wrap, `57f5516..57f553a` first compares physical row zero (logical index f) to q using exactly twenty bytes. Signed comparison is normalized to 0xff/0/1 without changing its equality/sign meaning.

* Equality jumps directly to `57f5699`. R14 still equals f and EAX is zero, so it returns that seam index. It does **not** perform a last-equal search.
* If seam key > q, `57f5545 -> 57f560d` searches the first segment. Global nondecreasing order makes every second-segment key >= seam > q, so all possible hits/insertion are confined to the first segment.
* If seam key < q, the second-segment branch searches there. Every first-segment key <= seam < q, so adding f to its hit/insertion index gives the global logical position. A second segment of length one bypasses only the loop, not the final comparison.

Therefore the CONTRACT seam/segment-last relation is exact for all nondecreasing live keys, including duplicate runs spanning the seam or following it. On a miss, the global insertion count is the number of logical keys smaller than q. On a hit, returned index is always below n. No key padding or weight enters any comparison. The ordinary memcmp sign/equality/frame premise is indispensable; import naming alone cannot prove it.

## 5. Selected-key fold and missing keys

The first iterator call at `4e44c48` either returns null, causing a zero return through `4e44def`, or supplies the first actual key. The accumulator begins at zero. Before lookup, it is saved at stack+8 (`4e44c91`) because RBX is reused for the map first word.

Since c is not the sentinel, NEG/JNO at `4e44cbf..4e44cc5` always chooses `4e44da0`. The lookup's status-low-bit check at `4e44dab` and unsigned index<n check at `4e44db3` guard the weight read. For a hit, `h+i < 2*c`, and one conditional subtraction in `4e44dbe..4e44dcf` gives `(h+i) mod c`. The address is d+32*p(i)+24. Valid backing spans prevent shifts/additions from wrapping or reaching padding/inactive rows.

At `4e44c60`, the saved accumulator is restored, the found weight is added, and two carry-conditional moves clamp on unsigned overflow. If x+w<=U, the addition is exact and both CMOVB operations keep it. If x+w>U, carry is set; the first conditional move selects U and the second installs that value in RBX. MOV instructions between ADD and the conditions preserve flags. Thus the update is min(U,x+w).

On a miss, the path `4e44ca0..4e44cb6` asks for the next actual key while leaving the saved accumulator unchanged. Further misses reuse that saved sum. If the iterator then returns null, `4e44de8` reloads it before return. On a hit followed by exhaustion, RBX already contains the updated sum and `4e44df1` returns it. These different return joins matter: simply tracking the reused RBX map-capacity word would misread the miss case.

Inductively, after each processed occurrence, the saved/current accumulator is the saturation of all successful occurrence weights so far. Missing keys contribute zero. The identity `min(U,min(U,x)+w) = min(U,x+w)` for nonnegative x,w yields B as stated. Native saturation does not bypass the next iterator call or subsequent comparisons/reads. All N occurrences are consumed; this is not an early threshold check and not a unique-key sum. Returned B/S/P values alone cannot distinguish a pure source optimization that skips work after its result is already determined under the same stability premises. No future value-only corpus may claim to detect such observationally equivalent early termination; preserving explicit traversal is a separate source/control-flow policy if chosen.

## 6. Every live map weight exactly once

After retaining B in RBX, the predicate rereads M. Its non-sentinel route at `4d3e24c..4d3e2ce` creates tag 2 and two span pairs. For n>0, canonical h yields first span `[d+32*h, d+32*(h+a))`, where a=min(n,c-h), and second `[d,d+32*b)`, where b=n-a. The branch at `4d3e271` handles n>c-h; otherwise it sets the second length to zero. For n=0, all span endpoints equal d and no capacity/head arithmetic is used. All endpoints are representable by the input premises.

At `4e40700..4e40704`, tag 2 selects the flat path; no tree traversal/panic site can be reached. The loop checks first cursor against first end, then either reads row+24 and advances by 32, or checks the second pair. It never reads an empty span. A nonempty first span is nonnull by premise, so the defensive zero-cursor return at `4e40720..4e40723` cannot truncate it.

When the first span ends and the second is nonempty, `4e4074a..4e40756` installs the second pair as active and changes the saved other pair to `[old_first_end,old_first_end)`. It immediately adds the first second-span row, which is valid/nonempty here. After the second span ends, the saved pair is empty and the function returns. Thus a switch occurs at most once and every logical live row is visited exactly once in order; no double counting or empty read occurs. Inactive capacity is never visited.

ADD at `4e40729` and the two CMOVB instructions at `4e40730/4e40738` implement the same saturation identity. The intervening MOV and LEA preserve carry; address advance does not replace the carry result. Starting from zero, the returned RAX is therefore S. The flat path performs no calls or input writes. This proof does not cover the preserved tag-not-2 tree branch.

## 7. Wide comparison and observable result

At `4d3e2e4..4d3e302`, the second sum S is copied into RCX and RSI. SHR by 63 creates the high limb of 2*S; ADD RCX,RCX creates its low limb. Unsigned MUL of saved B by 3 creates `(RDX,RAX)`, the high/low limbs of 3*B. Both mathematical products are below 2^66.

CMP of the low limbs sets borrow b. SBB of the high limbs sets final unsigned borrow exactly when `high(2*S) < high(3*B)+b`. The left high limb is 0 or 1, and the right is 0,1 or 2, so adding b cannot wrap. SETB writes AL=1 iff 2*S<3*B, not <=. Zero/zero and exact ties produce zero. No signed comparison, modulo-only comparison, or floating-point approximation is involved.

This establishes only the native AL result and the two separately observed full-RAX fold results. SETB does not zero all remaining RAX bytes. Exposing a safe result struct with B/S/P is a deliberate API observation, not a recovered struct-return ABI.

## 8. Memory effects, ordinary completion and proof limits

The complete predicate writes stack descriptors only. The selected fold writes stack spills and a private copied descriptor; the key iterator's stores are confined to that descriptor. The lookup writes only its stack query-pointer spill, call frames and saved registers. The flat total fold writes only its stack save/call frame; accumulation is in registers. There are no normal-route stores into M, K, tree nodes, physical rows, or query key bytes. The input/private-frame separation and ordinary import frame premise are therefore enough to preserve one stable input view across both folds. Unused copied fields do not become hidden callback inputs.

Loop variants are the exact selected remaining count, finite tree heights/ascent paths, decreasing segment-search width, and finite live row counts. The admitted structural/count invariant avoids iterator panic edges. Tag 2 excludes total-tree failure edges. Valid nonwrapping spans avoid malformed-pointer/zero-cursor exits. Under ordinary memcmp return and machine/stack premises, these facts establish normal completion, rather than merely a vacuous 'if it happened to return' result. They do not establish what the machine does when a premise fails, nor native exception/LSDA, allocator, signal or concurrent behavior.

Safe malformed-view rejection, canonical empty-head admission, host transport limits and any host resource outcome are separate policies, not facts inferred from those unreachable/malformed native branches. A supplied complete sequence is an input value projection with an explicit K correspondence premise, not evidence of original source set uniqueness or live reachability.

## Remaining obligations and EXPAND

The manual five-body derivation is complete for this bounded flat-map value domain. It still needs parent/peer acceptance of exact document hashes and a maintained static verifier/negative controls before being used as a source-admission foundation. Runtime import implementation, original constructors/type names, higher consensus policy, non-flat maps and native invalid-input behavior remain explicit unknowns. The next authorized stage, if granted, is independent pre-code expectations and controls; no source or reference is created by this proof.
