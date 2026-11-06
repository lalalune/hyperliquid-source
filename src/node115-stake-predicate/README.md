# Node115 flat-map stake predicate

Independently authored, dependency-free Rust for the conditional selected-key
and all-live-weight operation in Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The library is allocation-free and uses borrowed safe value inputs. Its structs
and errors are chosen host interfaces, not the native ABI.

Pass physical rows, a canonical head/live view, and the complete selected-key
sequence to `predicate`. Live keys must be nondecreasing in unsigned twenty-byte
order. Equal map keys may carry different weights. A wrapped seam equality picks
physical row zero; other queries select the relevant segment's last equal row.
Misses add zero, and repeated selected keys contribute each time. Selected and
total folds saturate independently before the exact strict comparison
`2 * total_sum < 3 * selected_sum`. Zero/zero and ties are false.

The standalone driver reads only stdin and accepts no arguments. Each ASCII,
LF-terminated TSV record has six fields:

```text
id<TAB>capacity<TAB>head<TAB>live<TAB>physical_rows<TAB>selected_keys<LF>
```

Rows use comma-separated `40_lowercase_hex:canonical_u64` entries; selected keys
use comma-separated forty-character lowercase hex. `-` means an empty list.
IDs are unique, case-sensitive ASCII letters/digits/underscore/hyphen, 1..64
characters. Decimal integers have no sign or leading zero. Capacity equals row
count. Input limits are 16 MiB, 8,192 records and 4,096 rows/keys per record;
the library has no such artificial count limits. Empty input is valid.

For valid transport, output preserves ID order and case:

```text
id<TAB>ok<TAB>selected_sum<TAB>total_sum<TAB>0_or_1<LF>
id<TAB>bounds<LF>
id<TAB>order<LF>
```

Bounds errors take priority over ordering. Arguments or malformed input return
status 2 with empty stdout. The complete input is checked before stdout is
written. Output I/O failure returns 1 and may leave partial output after valid
input; this is not an atomic-output promise. Successful runs return 0 with empty
stderr. Expectations never enter this source or the driver process.

Build this new host crate with Rust 1.95.0 using `cargo build --offline --locked`.
Its manifest and lockfile describe this independently authored component only;
they are not a recovered original workspace/dependency graph.

Native correspondence assumes stable valid sorted flat storage, ordinary
preserving `memcmp`, valid native frames and a selected sequence equal to the
complete native key-tree traversal. Original constructors, tree-map storage,
native ABI/errors/effects, higher consensus eligibility, current-network and
full-node equivalence remain unresolved. Values cannot certify every read/call
or distinguish every pure equivalent early stop. The source nevertheless keeps
complete folds. All full-scope acceptance gates remain false.

Evidence belongs in
`research/work-items/RE-008-node115-saturating-stake-predicate`. At initial
authorship the native contract, 40 manual cases and 8,011 input/expectation pairs
were frozen; Rust builds and comparisons were still pending. Actual validation
must be read from the packet's validation record when it is added.
