# Node #115 flat RPC store values

Independently authored MIT Rust for the conditional flat-store search and
all-or-nothing materializer relation. This is bounded RE-008 / consensus
state-retrieval work, with RE-001 static bindings,
for Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The library uses `core` and `alloc`, has no external dependencies, and forbids
unsafe code. The stdin driver uses the standard library. Rust 1.95.0 is pinned
by the repository.

Offline locked debug and release builds each matched all 13,957 frozen inputs.
Twelve deliberately incorrect source variants were detected in both profiles
through value differences, with successful builds, zero-exit executions and
complete valid output. All 80 transport controls passed. The Linux x86-64
library was built but not executed. See the [evidence packet](../../research/work-items/RE-008-node115-rpc-flat-materializer/README.md)
for commands, raw results, independent reference qualification and limitations.
These finite source/reference checks do not establish native-runtime equivalence.
All 92 full-scope gates remain false.

## Supplied-state API

`Row` contains a 32-byte key and an opaque `u64` value. `RingView::new` borrows
the physical row slice, taking its length as capacity, plus a head and live
length. It rejects invalid headers, zero live values and decreasing live keys.
Only live rows are checked; unused rows may be unsorted or contain zero values.
These refusals are chosen host policies, not native failure discriminants.

`search` compares actual keys in unsigned byte-lexicographic order. A hit returns
logical index, physical index and the stored value. A miss returns a logical
insertion index, which can equal the live length. Empty stores return insertion
index zero. In a wrapped store, equality with the first key of the second
physical segment returns that seam index immediately. Otherwise the selected
segment's binary search chooses its last equal key. This preserves the observed
duplicate rule; it does not rely on a standard library's unspecified duplicate
selection.

`materialize` searches the actual supplied query keys in order. It returns
`Some` of all selected values, preserving repeated queries, only when every
query hits. The first miss returns `None`; a temporary prefix is not returned
as success. Empty queries return `Some` of an empty vector. The source short
circuits at the first miss, but the value API does not expose a read/callback
trace. Identical failure outputs alone cannot establish the number of reads.

No stored value is dereferenced or interpreted as a reference count. Native
correspondence requires valid stable objects, sorted live keys, ordinary
preserving comparator/helper returns and successful reference acquisition at
**every reached increment**. An initially nonnegative count alone is not enough
for repeated acquisitions: an increment from signed maximum wraps, and a later
increment can violate the native normal-return premise. Native allocations,
growth, locks, tracing, drops and actual reclamation are not implemented here.
The library's vector allocation behavior is not claimed to match the capture.

The selected search and materializer are the complete native bodies
`0x57f5ee0..0x57f60cc` and `0x50f95f0..0x50f9720`. Their byte census predates this
implementation. The existing [lookup-prefix packet](../../research/work-items/RE-001-node115-rpc-lookup-prefix/README.md)
supplies credited lookup/collector context; the materializer's failure discards
that internal prefix. Native failure specifies only the first output word;
this API does not invent values for inactive output words. No native ABI, key
type, wire protocol, full RPC service, runtime or whole-node equivalence is
claimed.

## Stdin-only driver

The binary is `node115-rpc-flat-driver`. It accepts no arguments, files or
expected answers. Supply seven ASCII TSV fields per LF-terminated row:

```text
case_id<TAB>operation<TAB>capacity<TAB>head<TAB>live_length<TAB>physical_rows<TAB>queries
```

Operation is `S` for one search or `M` for materialization. IDs contain 1–64 ASCII
letters, digits, underscores or hyphens and must be unique within the invocation.
Counts are canonical unsigned decimal with no leading zero except literal `0`.
Capacity is at most 256. Physical rows are exactly capacity comma-separated
80-character lowercase hex records: 64 hex characters for the key, then 16 for
the value. The value text is a conventional most-significant-digit-first integer,
not native-endian memory. Capacity zero uses `-` for physical rows.

Queries are comma-separated 64-character lowercase hex keys, or `-` for none.
`S` requires exactly one; `M` accepts zero through 32. The driver allows at most
16,777,216 stdin bytes and 1–16,384 records. These are driver limits, not library
or native limits. CR/CRLF, non-ASCII bytes, empty records, malformed fields and
invalid supplied rings are refused.

Output preserves input order and uses these LF-terminated forms:

```text
case_id<TAB>H<TAB>logical_index<TAB>physical_index<TAB>value16hex
case_id<TAB>N<TAB>insertion_index
case_id<TAB>V<TAB>comma-separated value16hex, or - when empty
case_id<TAB>F
```

All input rows and domain checks finish before the first stdout write. Malformed
input exits with status 2 and empty stdout. A subsequent output I/O failure may
leave partial output; it is not covered by the malformed-input guarantee.
The driver reads only stdin and arguments and writes only stdout/stderr. It has
no reference, corpus, artifact, filesystem, network or captured-code access.
