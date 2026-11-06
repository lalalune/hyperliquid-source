# Conditional contract: node115 flat-map stake predicate

This private pre-code contract is independently derived from five complete native bodies. It authorizes no source, oracle, corpus, tests or execution. It concerns node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` at repository base `05bc2de303c05525b71e7e257426e741bc66a390`. Addresses are preferred ELF virtual addresses; an ordinary load bias changes addresses, not the stated relative relations.

## Operation and observation

Let `U = 2^64-1`, `sat(x) = min(U,x)` for a nonnegative mathematical integer x. M is the supplied flat map and Q is the complete sequence of actual twenty-byte keys produced from K as defined below. Each logical live map row has a twenty-byte key and an unsigned u64 weight. Weights may be zero or U; they are not handles or reference counts.

For each occurrence q in Q, use the exact flat lookup selection below. If it finds a row, contribute that row's weight; otherwise contribute zero. Preserve all occurrences without deduplication. Define

* `B = sat(sum of those contributed weights)`;
* `S = sat(sum of every logical live map row's weight, exactly once)`;
* `P = (2*S < 3*B)`, with exact wider-than-u64 products.

Under the native domain and call/frame premises, the first fold returns B in RAX, the second returns S in RAX, and the predicate returns P as AL equal to 0 or 1. This is an ordinary-termination/value relation. It makes no assertion about upper bits of the predicate's final RAX, a C/Rust signature, or an object returned by the native ABI. A proposed safe API may expose B, S and P as its own observation struct; that choice does not invent a native three-field return.

Both folds saturate before comparison. It is not a checked-overflow, wrapped-u64, unbounded-ratio or floating-point value relation. The native control flow does not stop traversal on saturation. That control-flow observation is separate from the returned values: under the stable-input premises, B/S/P alone cannot distinguish every pure early-termination implementation with identical results. No selected-key uniqueness, ordering, membership eligibility, or `B <= S` property is assumed. In particular, repeated selected occurrences can make B larger than S. The two folds execute sequentially; stable inputs, rather than native atomic-snapshot machinery, relate them to one M.

## Exact owning bodies and credits

| Role | Full half-open FDE | Bytes | Body SHA-256 |
| --- | --- | ---: | --- |
| Predicate | `4d3e1a0..4d3e30d` | 365 | `974e193d7cdb06afb981beb3ef46a1db7b65bf1515b052fa4461a19904953bce` |
| Selected-key fold | `4e44c00..4e44e03` | 515 | `42e77239f84af8106308d3935a0f3af00544a55c8b775b21e3e67888a5ad4d3b` |
| All-weight fold | `4e406f0..4e4098d` | 669 | `c797a64bb012f190b385812c5d50754e4b55bf0d4b4a03792e31c72ff29caadf` |
| Key iterator | `5138730..5138946` | 534 | `5db9cca89e80ff8bc51e3b4a6e1d3d65bef05df707379ff8bd1245493fdee5da` |
| Flat lookup | `57f54e0..57f56ab` | 459 | `8d982d28034aa0ebcd1cf2246366f03877b75d885c6cdf8f732c7ab8dada3d5e` |

The complete denominator is 2,542 bytes / 643 native rows, including branches excluded from this contract. No excluded tree-map or panic bytes are removed to improve a coverage measure. The containing CIE/FDE records and all selected instruction bytes are authenticated in the private native admission. No binary instructions were executed or emulated.

Merged PR 2472 (`RE-001-node115-validator-stake-saturation`, `thegeronimo`) already establishes the three-body saturation/predicate cluster, location association, and conditional arithmetic. Proposer PR 2033 already retains the flat lookup and implements real ordered twenty-byte key snapshots and saturating totals in its packet-local Rust `prepare()`. Heartbeat PR 2308 records calls to the key iterator. Existing `src/node115-tree-next` is credited as prior owned-tree iterator/value work, not a dependency or new discovery here. Existing checked `node115-weighted-fastfold` implements a different provider/status-based suffix. Prior RPC PR 2716 closes the analogous 32-byte-key / 40-byte-row flat search and materializer; its seam/order-statistic reasoning is credited. This operation has twenty-byte keys / 32-byte rows and actual selected/all weighted aggregation. It is not a renamed search-only contribution and will not depend on pending runtime code.

## Native input and frame domain

The entry RDI points to M, entry RSI to K. Header reads and every subsequently used data span must be live and readable, with nonwrapping 64-bit addresses. The ordinary ABI stack/call alignment must support the observed pushes, call return addresses, local frame ranges and aligned stack `movaps` stores. No logical input aliases those writable frames. All viewed input bytes remain stable throughout the entire operation, including across import calls; no signal, foreign writer or helper mutates them. Read-only views may share bytes only if all their stated simultaneous invariants hold. Owned key-tree node identities and parent/child edges must form a tree, not a DAG with reused children or a cycle.

Native integer loads in these bodies are x86 loads, not proof of an original Rust reference or layout. The proof requires readable bytes and valid address calculations; it does not infer Rust aliasing validity merely from the machine instructions. A future safe representation uses ordinary safe borrows and its own layout.

### Flat map M

The 32-byte header contains u64 capacity c at +0, data word d at +8, head h at +16 and live length n at +24. Its first word must not equal the excluded tree-map sentinel `0x8000000000000000`.

For n > 0, require `0 < c < 2^63`, `0 <= h < c`, `0 < n <= c`. The physical storage has c rows of 32 bytes, with all needed row addresses and one-past span endpoints representable without 64-bit wrap; in particular, 32*c and h+n must not overflow. Every live row's bytes 0..19 and 24..31 are readable. A row's bytes 20..23 are ignored padding. Define physical index `p(i) = (h+i) mod c` for `0 <= i < n`. Logical live keys `key[p(i)]` must be nondecreasing in unsigned lexicographic byte order. Equal keys, arbitrary differing weights, and arbitrary inactive physical rows are allowed. Each nonempty span's starting address is required nonzero. The all-fold explicitly treats a zero first active cursor as an early return; this contract excludes that degenerate live-span representation. A null unused data word when n=0 is addressed separately.

For n = 0, the native flat route makes no row dereference. It reads the header/data word but does not need the capacity/head arithmetic or an allocation at d. Capacity may be zero and d may be null/dangling as an unused word; the first word must still not be the sentinel. Even noncanonical h/c words are ignored on this particular native route. This is an observed inert-state fact, not an endorsement of malformed source container constructors. The proposed safe API intentionally has the stricter, explicit canonical empty-view policy below.

The full tree-map sentinel route is excluded. Its embedded search and total traversal are preserved as native evidence but have no new semantic claim here.

### K and its complete key sequence

K's first two words, root r at +0 and height H at +8, are always readable. If r is nonzero, count N at +16 is also readable. If r is zero, the predicate constructs remaining count zero without reading K+16. If r is nonzero and N is zero, the iterator returns null before dereferencing r or using H. In both inert cases Q is empty; no claim is made that an arbitrary ignored r/H/count combination is an original valid source container.

For r != 0 and N > 0, the following structural domain is sufficient:

1. r names the root of a finite acyclic tree of height H, leaves at height zero. Every internal node has exactly k+1 readable, nonnull child pointers to nodes of height one less. Each node has `0 <= k <= 11` active key slots; the root/other nodes need no source-library minimum occupancy assumption for this traversal proof.
2. Node fields: parent pointer at +0; key i's twenty bytes at +8+20*i; own child-position u16 at +0xe4; live key count k u16 at +0xe6; child j pointer at +0xe8+8*j. All required spans/endpoints are live/nonwrapping. Root parent is zero. A nonroot's parent pointer and child-position j exactly identify the edge from its parent, `0 <= j <= parent.k`.
3. All node keys are arbitrary twenty-byte values. No key comparison, sortedness, uniqueness, set constructor or original type name is needed or established. Physical node identity/topology is still coherent; arbitrary key order is not arbitrary pointer topology.
4. N is exactly the sum of k over every node, with that count representable as u64. H and every depth/count/cursor operation are representable; actual finite node spans and height-consistent topology ensure the traversed depths never exceed H. Define Q by the ordinary complete in-order expansion: for an internal node, child0 sequence, key0, child1 sequence, key1, ..., key(k-1), childk sequence; for a leaf, its k keys. Thus length(Q)=N.

The proof relates the native initialized iterator to this actual Q. A future safe API may accept Q as a complete supplied sequence, but its correspondence is conditional on Q equaling that in-order expansion for the native K being compared. It does not validate a live native K, invent helper results, establish that every supplied sequence occurs in an original source-level set, or transform repeated keys into unique ones. All occurrences remain part of the value operation.

## Exact lookup selection

For n=0, every query misses. For n>0, let `a=min(n,c-h)` and `b=n-a`. If b=0, search the entire contiguous live segment and select the last equal key if any. If b>0, the seam is logical index a, physical row zero:

* If q equals `key[0]`, select index a immediately, even when other equal keys occur later in the second segment.
* If q is smaller, search only the first segment; choose its last equal key if any.
* If q is larger, search only the second segment; choose its last equal key if any, translated by +a to logical indexing.

On no equal key, the native helper reports status low bit 1 and the ordinary insertion position (number of smaller logical live keys). On a hit it reports status low bit 0 and a logical index below n. The selected fold nevertheless checks both the low status bit and `index < n` before reading a weight. It computes physical index using one subtraction from h+index, justified by canonical h and n<=c. No source-level native error is inferred from a skipped miss.

Unsigned byte order means exactly the first twenty key bytes; neither the padding nor weight affects comparison. Native `memcmp` receives length 20 at each call. This is a conditional ordinary import contract, not evidence about the actual loaded libc implementation.

## Calls, effects and exclusions

There are 16 syntactic call sites in the five full bodies. The flat-domain ordinary closure contains direct calls among these functions and imported `memcmp` only. The three selected-fold iterator call sites differ by first / hit / miss continuation; they are not a fixed dynamic call count. The map-tree-only memcmp site and four panic sites remain excluded by the admitted control flow.

The import slot `0x64dfb50` has an exact `R_X86_64_GLOB_DAT` relocation, symbol index 12, undefined function `memcmp`, addend zero. Assume each reached call returns normally, preserves the ABI callee-saved registers/stack and caller input frames, and returns the standard unsigned-byte first-difference sign/equality comparison of exactly the twenty requested key bytes. This constrains the comparison result, not the import implementation's physical read widths or memory-access trace. It must not mutate input or caller-private state. The name/relocation does not prove runtime binding or these frame guarantees. POSIX Issue 8 documents the abstract comparison relation at `https://pubs.opengroup.org/onlinepubs/9799919799/functions/memcmp.html`; the parent retained that primary page separately. Its documentation is not another independent capture lineage.

The failure slot `0x64df830` is a symbol-zero RELATIVE relocation to `0x1680c10`. Its internals and failure/unwind behavior are not needed because the valid key-tree invariant avoids both iterator panic edges, and tag 2 avoids both all-fold tree panic edges. No failure helper is assumed to be harmless or noreturn to manufacture a normal-path proof.

Normal instructions write only private stack/local iterator storage; the map, K, node contents and rows are read-only under the premises. The iterator updates descriptor offsets +0, +8, +16, +24 and +64, all inside the selected-fold's private copied descriptor. It never overwrites the map pointer at descriptor +72. The unused back-cursor fields and saved K pointer are copied, not dereferenced by this operation. Timing, reads, dynamic call counts, CPU behavior, allocation, locks, diagnostics, exceptions, invalid-input machine behavior and high-level consensus validity are not API observations.

## Proposed safe API admission, separate from the native theorem

Candidate public paths remain `src/node115-stake-predicate` and `research/work-items/RE-008-node115-saturating-stake-predicate`. No source is created by this document.

A minimal dependency-free borrowed value API takes physical rows `(twenty-byte key, u64 weight)`, head h, live length n and the complete supplied selected sequence Q. Its capacity is the number of supplied physical rows. It validates the real view before computing the operation:

* n<=c; if c=0 then h=0 and n=0; if c>0 then h<c **even when n=0**;
* counts and native stride/span calculations fit the declared value/native-correspondence bound and the host's actual safe storage/index domain;
* logical live keys are nondecreasing; no order/value constraint on inactive physical rows;
* all twenty-byte selected values and every u64 weight, including zero, are admitted; Q is not sorted or deduplicated by the API.

Malformed views receive a new explicit safe admission refusal. That is not a recovered native error/tag, panic, or validation order. In particular, refusing noncanonical empty h/c differs from the broader native inert empty route. The theorem only identifies admitted safe views with matching native representations and Q correspondence. The API need not allocate or model native tree storage; if its eventual implementation introduces any fallible host resource step, successful source correspondence must additionally assume that step succeeds, with a separately labelled host outcome.

B and S are useful safe observations of internal fold results; P is the native AL observation. This API must compute them from actual supplied keys/weights, not accept a precomputed basis, fake found/missing callbacks or expected corpus data.

## Remaining admission work

`PROOF.md` supplies the bounded manual derivation. The raw binding receipt is static evidence, not a generated behavioral model. Before implementation: parent/peer must review this exact contract, choose any necessary revisions transparently, qualify operative static controls and independent pre-code expectations, freeze their provenance, then separately admit source. Live ownership review is parent-owned. No full protocol or all-target runtime equivalence claim is made.

## EXPAND

After the exact proof gate, derive an independently expressed order-statistic / mathematical-sum reference and complete input-only cases, including repeated selected keys and equal-key seam weights, without importing source or executing the capture. Keep the tree-map sentinel and higher consensus policy outside this contribution.
