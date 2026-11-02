# Frozen input-only fixture protocol

All integers below are unsigned little-endian; fixed hashes are exactly32 bytes.
`blob` is u32 length followed by precisely that many bytes. Corpus IDs `C000000`
and later are opaque sequential IDs, not semantic labels. Files are UTF-8 lines
`ID TAB lowercase-hex LF`. `vectors.tsv.gz` contains only input frames;
`expected.tsv.gz` is held by the parent comparator. Diagnostic names/categories
and both hashes are in `cases.jsonl.gz`, never sent to the source client.

The independent oracle `corpus.py` models lookup as a finite relation: for each
requested key, the values whose full32 bytes equal it; the least absent request
index determines failure. It does not walk native or std tree nodes. Counts are
mathematical multiplicities of explicit identity IDs. The corpus has361 cases:
322 ordinary native projections,12 provided-path invalid-unused-view projections,
7 empty-hash invalid-unused-map projections,11 new safe view refusals and9 safe
count-admission boundaries. No huge allocation or captured evaluation is used.

## Input frames

Kind byte1 is a join input, followed in this order by:

1. Opaque block/proof blob, then12 raw time bytes.
2. u32 pool object count, then that many byte blobs. Each entry owns a distinct
   object even when bytes equal another entry. Its zero-based ID identifies it.
3. Hash-view blob, then map-view blob, both retained as raw bytes by outer framing.
4. Option byte0 for absent supplied rows or1 followed by u32 row count and rows
   of `hash32 || object_id:u32`. Supplied object IDs must be in the pool.

A valid hash view is `count:u64 || hash32[count]`, exactly its declared length.
A valid map view is `count:u64 || (hash32 || object_id:u32)[count]`, exactly its
declared length, with strictly increasing unique unsigned-byte keys and in-pool
IDs. Bad view lengths, ordering or IDs are decoded to safe view errors, never
reinterpreted as native pointers. An invalid map has no constructed source map.
The fixture driver may parse a view into Result before calling the API, but
only the API's provider invocation counts as access to that checked view; it
must not derive or send an expected access policy. Unused invalid view Results
are deliberately admissible. Option errors, unknown kind, invalid supplied ID,
outer truncation and trailing bytes are malformed whole-frame inputs.

Kind byte2 followed by one u64 count asks the actual source admission helper for
native40-byte span arithmetic. The helper is also used by the join operation.
These are new safe count-admission cases, not native tags or allocated vectors.
Expected values assume a 64-bit Rust host, as pinned for qualification; the API
must also respect a narrower host's usize/isize capacity if ported there.

## Observations and output frames

For each join, the driver owns one Arc per pool object; each valid map entry owns
a clone. If rows are supplied it retains one keeper of that outer Arc and moves
one additional outer Arc reference into the input. The keeper's inner values are
owned once, regardless of outer Arc strong count. The block has no external
strong keeper; the driver retains a Weak identity observer. Hash/map providers
borrow independently prepared views and do not retain the block.

While the result is alive, serialize:

1. Kind1, status byte, hash-provider calls byte, map-provider calls byte,
   block-Weak-live byte, row-identity byte.
2. On success: actual block blob, actual12 time bytes, u32 output row count,
   then each actual `hash32 || pool_id:u32 || actual_value_blob`.
   On missing: only the exact missing hash32. Other refusals have no payload.
3. u32 pool count, then for each object `live_strong:u64 || after_drop_strong:u64`.
   These are **source** ownership measurements, not native raw refcount values.
4. Block-Weak-live byte after dropping the result (zero), u32 outer-row strong
   count while result was alive, u32 supplied-keeper count after result drop.
5. Map-valid byte; when valid, u32 entry count followed by each actual sorted
   `hash32 || pool_id:u32 || actual_value_blob`, observed after the call.

Status0=success,1=missing hash,2=hash view refusal,3=map view refusal,4=count/span
refusal,5=reservation refusal. Allocation success is assumed for finite value
fixtures; status5 is not manufactured by a flag. Row identity0=no output rows,
1=the exact supplied outer Arc,2=a newly created outer rows Arc. The expected
outer count is2 for supplied success,1 for newly created success, and0 on errors
(a supplied input cannot produce a normal error). The supplied keeper remains1
after result drop. Weak identity must compare pointers, not merely block bytes.

For each pool object v, baseline source owners are one pool owner plus the
number of map entries using v plus the number of supplied rows using v. A newly
constructed successful result adds its row multiplicity while alive; provided
success does not duplicate inner Arc owners. After result drop, all cases return
to baseline. On failure, every temporary prefix clone must have been released.
The complete map's IDs and byte contents remain unchanged. This demonstrates
safe sharing/lifetime, not native atomic instruction or destructor equivalence.

Kind2 output is byte2, success byte, and if admitted u64 `40*count`. On a 64-bit
host admission means `count <= floor((2^63-1)/40)`. No other output is accepted.

The comparator must require exact IDs, count, ordering, widths and bytes; reject
duplicate/missing/extra/malformed lines and unknown outcomes. The input client
must reject extra command arguments and malformed whole frames instead of
repairing/sorting them silently. Map view sorting is admission-only: a valid
map must already be sorted, and requested/output rows must never be sorted or
deduplicated. No benchmark, timing, networking, signature or wire-format claim
follows from this test protocol.
