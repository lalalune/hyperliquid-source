# node115-attachment-reader

A source-owned decoder for the selected node #115 attachment vector. Each row
contains a 32-byte ID and an owned byte blob. The decoder preserves wire order,
repeated IDs, trailing input, and the selected native reader's cursor and budget
commits on failure. It reuses `node115-u64-reader-state` for both integer reads.

```rust
use node115_attachment_reader::Reader;
let mut reader = Reader::new(&[0, 99], Some(8), 0);
assert!(reader.read_attachments().unwrap().is_empty());
assert_eq!(reader.remaining(), &[99]);
assert_eq!(reader.charged(), 8);
```

`charged` is typed-reader accounting, not the wire byte count. `None` disables
accounting and preserves the initial counter. The API returns no partial rows on
failure; it does retain the cursor and charge changes already made. Rust owns
completed rows and releases them when a later row fails. Error enums and `Arc`
layout are source interfaces, not a recovered native ABI.

See [the evidence and limits](../../research/work-items/RE-005-node115-attachment-reader-state/README.md).
