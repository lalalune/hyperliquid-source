# RE-001: plain-table index builder, per-key record and histogram dump (node #115)

## Task and bounded question

Task: RE-001. Bounded question: how does the plain-table index builder
in `rocksdb/table/plain/plain_table_index.cc` record one key (hash,
run-length histogram sample, chunked entry store) and dump the finished
index — the bucket-count computation, the chain gather, the histogram
render and log, and the serialization with its per-bucket slot array
and suffix map?

Artifact: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json). All evidence below is bound to that digest.

## Windows

| window | FDE | file |
|---|---|---|
| record host | 0x6198900..0x6198ce2 | host-6198900.objdump.txt |
| dump-host cleanup | 0x6198ce2..0x6198d34 | host-cleanup-6198ce2.objdump.txt |
| dump host | 0x6198d40..0x6198f4d | host-6198d40.objdump.txt |
| subrec append | 0x6198790..0x6198853 | subrec-6198790.objdump.txt |
| chunk-ptrs push-back | 0x61985f0..0x6198775 | pushback-61985f0.objdump.txt |
| throw stub | 0x6198776..0x6198790 | throwstub-6198776.objdump.txt |
| bucket-count computer | 0x6198230..0x6198283 | bucket-count-6198230.objdump.txt |
| gather | 0x6198290..0x6198364 | gather-6198290.objdump.txt |
| serializer | 0x6198370..0x61985e2 | serializer-6198370.objdump.txt |
| varint encoder | 0x61bd410..0x61bd4e9 | varint-enc-61bd410.objdump.txt |
| log dispatcher | 0x5fceda0..0x5fcee93 | log-5fceda0.objdump.txt |
| histogram record | 0x606b130..0x606b1b3 | record.txt |
| record thunk | 0x606b1c0..0x606b1cd | record_thunk.txt |
| bucket index | 0x606afa0..0x606b013 | bucket_index.txt |
| percentile | 0x606b260..0x606b4fe | percentile.txt |
| median | 0x606b500..0x606b511 | median.txt |
| average | 0x606b540..0x606b5b9 | average.txt |
| stddev | 0x606b5d0..0x606b6ae | stddev.txt |
| renderer | 0x606b6f0..0x606bc8d | renderer.txt |
| ToString entry | 0x606bc90..0x606bcd3 | tostring_entry.txt |
| hex encoder | 0x61c7e30..0x61c7fb6 | hex-encode-61c7e30.objdump.txt |

Excerpts were produced with, e.g.:

```
objdump -d --start-address=0x6198900 --stop-address=0x6198ce2 work/hl-node-115.bin
```

Mnemonics such as `endbr64` are genuine instructions present in the
target binary, not placeholders. The excerpts are verbatim objdump output,
whole-function. `export_excerpts.py` (committed here) regenerates them and
`frames.txt` from the binary. The histogram family (`record.txt`,
`record_thunk.txt`, `bucket_index.txt`, `percentile.txt`, `median.txt`,
`average.txt`, `stddev.txt`, `renderer.txt`, `tostring_entry.txt`,
`boundaries.tsv`) is re-shipped byte-identical from open PR #3371
(RE-001-histogram-stats-family-115); the hex encoder is re-shipped
byte-identical from open PR #3585 (originally #3561). `verify.py`
re-derives every excerpt from the binary, so a re-ship that drifted
would fail the packet check.

## Claim status

### Observations (read directly from the disassembly)

- The record host 0x6198900 takes `(owner, Slice key, u32 arg4)`. It has
  two direct callers: 0x618f237 (in FDE 0x618ecf0..0x618fbbe, passes the
  key returned by a virtual `*0x98` call) and 0x61a05cb (in FDE
  0x619fe30..0x61a0bc8, passes the fixed slice `("chain_ext.rs", 0)` —
  a zero-length key whose data pointer is that Rust source name).
- Entry test on `*(owner+0x758)`: 0 takes the compare path, non-zero
  goes straight to the main body (total-keys `+0x75c` incremented
  first). The compare path hex-encodes the key with flag 0 (raw copy)
  via 0x61c7e30 and compares it with the stored string at `+0x790`.
- On a key change: `+0x75c` increments, the finished run length
  `*(owner+0x760)` is recorded into the histogram at `+0x360` via the
  record thunk 0x606b1c0, then the main body runs. On an unchanged key
  with `*(owner+0x759) == 0`, only the counter path runs; with
  `+0x759` set, the stored hash `*(owner+0x764)` is re-appended with
  the current arg4 via 0x6198790, `+0x759` is cleared, then the counter
  path runs.
- Main body: `*(owner+0x760) = 0`; hex-encode the key again and
  move-assign it into `+0x790`; `hash = rocksdb::Hash(key.data,
  key.len, 397)` via 0x61c34a0 (seed immediate 0x18d at 0x61989f1) into
  `+0x764`; `+0x759 = 1`; append `(hash, arg4)` via 0x6198790;
  `+0x759 = 0`; then the counter path.
- Counter path: `*(owner+0x760) += 1`; if `*(owner+0x768) != 0` and
  the run length is a non-zero multiple of `*(owner+0x768)`,
  `+0x759 = 1`; `*(owner+0x758) = 0`; return.
- The dump host 0x6198d40 returns `(buffer, size)`. It has two direct
  callers: 0x618e680 (in FDE 0x618dcb0..0x618eca7) and 0x61a0771 (in
  FDE 0x619fe30..0x61a0bc8, the same enclosing function that calls the
  record host). It computes the bucket count via 0x6198230, allocates
  two zeroed arrays sized by `*(owner+0x770)`, gathers via 0x6198290,
  records the current run length into the histogram via the thunk,
  renders ToString via 0x606bc90, logs level 1
  `"[%s:101] Number of Keys per prefix Histogram: %s"` (0x957830) with
  the file argument `table/plain/plain_table_index.cc` (0x9577d0 —
  the eight bytes before it, at 0x9577c8, are `rocksdb/`, so the full
  path is `rocksdb/table/plain/plain_table_index.cc` but the rendered
  line carries the shorter form), serializes via 0x6198370, frees the
  string and both arrays, and returns the pair.
- The cleanup window 0x6198ce2..0x6198d34 is the dump host's
  landing-pad cleanup: three entries (dispose the ToString string,
  free vec2, free vec1; canary check; `_Unwind_Resume`), reached
  only by the dump host's landing pads at 0x6198f29/0x6198f35/0x6198f41.
- Subrec append 0x6198790 stores 16-byte entries `{u32 hash, u32
  arg4, u64 next}` into the chunked store at `+0x728` (entries per
  chunk at `+0x00`, current chunk at `+0x08`, chunk-ptrs vector at
  `+0x10..+0x20`, used count at `+0x28`). A full chunk allocates a
  new one of `entries_per_chunk*16` bytes via `operator new[]` and
  pushes it via 0x61985f0 when the vector is at capacity (inlined
  otherwise); a used count with bits above bit 59 jumps to the throw
  stub 0x6198776 (`__cxa_throw_bad_array_new_length`).
- Push-back 0x61985f0 is the standard `std::vector` push-back with
  doubling growth, capped at 0x7ffffffffffffff8 bytes, throwing
  length_error past the element maximum.
- Bucket-count computer 0x6198230: `*(owner+0x770) = 1` when
  `*(owner+0x778) == 0` or `*(owner+0x780) <= 0.0`; otherwise
  `(u64)((double)*(owner+0x75c) * (1.0 / *(owner+0x780))) + 1`
  (1.0 is the double at 0x4592b0).
- Gather 0x6198290: total entries = `((chunk_ptrs.end -
  chunk_ptrs.begin)/8 - 1) * entries_per_chunk + *(owner+0x750)`;
  for each entry in chunk order, `bucket = hash % *(owner+0x770)`,
  prepend to `vec1[bucket]` and count in `vec2[bucket]`; then
  `*(owner+0x774)` = sum over buckets with count > 1 of
  `count*4 + varint_len(count)`.
- Serializer 0x6198370: logs level 0 `"[%s:156] Reserving %u bytes
  for plain table's sub_index"` (0x958120) with `%u =
  *(owner+0x774)` — the suffix-map payload size, not the total
  reservation; total = `varint_len(bucket_count) +
  varint_len(total_keys) + suffix_size + bucket_count*4`; buffer =
  `(*owner)->vtable[0x18](*owner, total, *(owner+0x788), logger)`;
  writes `varint32(bucket_count)` then `varint32(total_keys)` via
  0x61bd410; per bucket: count 0 → slot `0x7fffffff`; count 1 →
  slot = the single entry's arg4; count > 1 → slot = `offset |
  0x80000000` and the suffix gets `varint(count)` then the count
  arg4 values in reverse chain order (head last), so the suffix
  lists each bucket's values in insertion order; logs level 0
  `"[%s:202] hash table size: %u, suffix_map length %u"` (0x9577f8)
  with `(bucket_count, suffix_size)`; returns `(buffer, total)`.
- Varint encoder 0x61bd410: unsigned LEB128, 1 byte to 0x7f, 2 to
  0x3fff, 3 to 0x1fffff, 4 to 0xfffffff, else 5 bytes; continuation
  bit 0x80 on all but the last byte; returns `dst + length`.
- Log dispatcher 0x5fceda0: returns early on a null logger; calls
  the logger's vtable slot 0x40 for its level and logs only when
  `logger_level <= requested_level`; level 5 goes to slot 0x18,
  otherwise slot 0x28 with `(logger, level, format, va_list)`.
- HistogramImpl vtable 0x64d2b80 (typeinfo
  `N7rocksdb13HistogramImplE`, typeinfo object 0x64d2b58, name at
  0x9753f0): slot 0x20 is the record thunk 0x606b1c0 (RELATIVE at
  0x64d2ba0), slot 0x30 is the ToString entry 0x606bc90 (RELATIVE at
  0x64d2bb0); all 16 slots resolve from `.rela.dyn` (see
  `vtables.tsv`). The record thunk has exactly three direct callers:
  0x606004c (inside the #3575 host 0x605feb0), 0x6198ae7 (record
  host) and 0x6198e2a (dump host). The ToString entry has three
  direct callers: 0x5ef0c43, 0x606007d (inside the #3575 host) and
  0x6198e3a (dump host).
- Histogram record 0x606b130: bucket = `bucket_index(value)` over the
  109 boundaries at global 0x6505d20; `buckets[bucket]++`; min/max/
  count/sum/sumsq update (min starts at the last boundary
  13000000000000000000, max at 0). Bucket index 0x606afa0 is a
  lower_bound binary search (first boundary >= value);
  `value >= last boundary` returns 108.
- Renderer 0x606b6f0 builds: `Count: %lu Average: %.4f  StdDev:
  %.2f\n`; `Min: %lu  Median: %.4f  Max: %lu\n` (literal 0/0 for
  min/max when empty; median is Percentile(50.0)); `Percentiles:
  P50: %.2f P75: %.2f P99: %.2f P99.9: %.2f P99.99: %.2f\n`; 54
  dashes + `\n`; one row per non-empty bucket:
  `"%c %7lu, %7lu ] %8lu %7.3f%% %7.3f%% "` (`[` with lower 0 for
  bucket 0, `(` with lower BOUNDARIES[i-1] otherwise) then `'#'`
  repeated `round(pct / 5)` times, then `\n`. Percentile walks
  buckets until the running total strictly exceeds
  `count * (pct / 100.0)` and interpolates inside the bucket,
  clamped to `[min, max]`; an empty bucket returns its lower
  boundary; past the last bucket returns `(double)max`.
- rocksdb::Hash 0x61c34a0 is NOT pinned here: its authoritative
  packet is dd12m54's open PR #3525
  (RE-001-hash-entry-61c34a0-115). It is recorded only as the record
  host's callee (seed 397). Its shape: `h = (len * 0xc6a4a793) ^
  seed`; per 4-byte word `h += w; h = (h*m) ^ ((h*m) >> 16)`; tail
  of 1–3 bytes sign-extended at shifts 16/8/0, then `h = (h*m) ^
  ((h*m) >> 24)`; a length that is a multiple of 4 returns h with
  no final mix, so `Hash(b"", 397) == 397`.
- Open PR #3575 names 0x6198900 and 0x6198d40 as its next candidates
  ("the other two record-thunk callers"); that forward reference is
  the only other PR mentioning them — neither host was pinned before
  this packet.

### Inferences

- The owner is the plain-table index builder in
  `plain_table_index.cc`: the log file path, the "Number of Keys per
  prefix Histogram" line and the "hash table size / suffix_map" line
  all name that file. The class name itself is inferred from the
  file, not from a symbol — the binary carries no usable symbol
  names here.
- `+0x770` is the dump bucket count and `+0x774` the suffix-map
  payload size; both are computed, never set by the hosts
  themselves.
- The allocator behind `(*owner)->vtable[0x18]` returns a writable
  buffer of at least the requested size; the model takes it as a
  callback.
- The first empty key takes the unchanged path (the stored key
  starts empty), so it records nothing — a quirk of the compare
  path, reproduced by the model and covered by a test.

### Unknowns

- The allocator object at `*(owner+0x00)`: its class and the
  identity of its vtable slot 0x18 are unresolved — the slot is
  called as `(this, total_size, *(owner+0x788), logger)` and returns
  the serialization buffer; the owner's construction code (which
  installs it) is outside the pinned windows.
- The `+0x758` flag's setter: the record host only ever writes 0 to
  it, and none of the three direct callers (0x618ecf0, 0x618dcb0,
  0x619fe30) writes it either; the flag is modeled as an input and
  both paths are pinned, but what sets it to 1 is unknown.
- The owner's construction: which code builds the owner struct
  (installing the `+0x228` logger, `+0x768` interval, `+0x778`
  gate, `+0x780` ratio, `+0x788`, the `+0x360` histogram and the
  `+0x728` store) is a separate work item — the two enclosing
  callers pass the owner in from their own frames.
- The record host's own exception path: its landing pads are not
  pinned here — the cleanup window 0x6198ce2 belongs to the dump
  host; the record host's LSDA was not examined.
- The `+0x788` qword's meaning (passed to the allocator call) and
  the `+0x778` gate's meaning are recorded as observed, not
  interpreted.
- The second record-host caller passes the fixed slice
  `("chain_ext.rs", 0)` — a zero-length key whose data pointer is
  that Rust source name; why that caller records an empty key is
  not established.
- The `"Reserving %u bytes"` log prints `*(this+0x774)` (the
  suffix-map payload) while the allocator call reserves the larger
  total; whether upstream intends the `%u` to be the suffix size or
  the total is not established from the binary alone.

## Model and tests

`tools/plain_table_index_115.py` models the two hosts, the chunked
store, the histogram (record / average / stddev / percentile /
ToString), the varint encoder, the bucket-count computer, the gather
and the serializer, with the allocator as a harness-supplied
callback and the log lines collected as records.
`tests/test_plain_table_index_115.py` (38 tests) covers the hash
against an independent transcription plus hand-computed anchors,
varint boundary lengths, bucket-index boundaries, the histogram
ToString exact text, the first-empty-key quirk, the sampling
interval re-append, the `+0x758` direct path, exact serialized
bytes for the empty and single-bucket cases, and a serialized
round-trip that re-parses the buffer and checks the suffix lists
each bucket's values in insertion order.

`verify.py` re-checks the packet against the binary: digest,
manifest, excerpt regeneration, sampled instructions byte-for-byte
against a fresh objdump run and the raw binary (fixed samples plus
3 seeded random gate spots), frames rows, the caller census,
relocations, vtables, literals, boundaries, and the model tests.
