# Attachment vector: one reader through reservation and nested failures

Partial RE-005 reconstruction for Linux x86-64 node #115, size 105896032,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
This integrates the attachment-vector child readers and their observable cursor,
accounting and owned-prefix behavior. It does not decode a whole ClientBlock,
prove a block valid, or establish the outer transport or asynchronous ABI.

## Prior work and remaining scope

#5065 (`RE-005-node115-clientblocks-attachment-budget`) established the vector's
40-byte reservation, refund and callback loop; #5062 established the blob budget
reader. `RE-001-node115-checked-read32` established the fixed 32-byte reader.
The existing `src/node115-u64-reader-state` owns integer cursor/charge behavior
and is reused unchanged. #6656 covers completed-prefix and outer Arc cleanup.
Those are prerequisites, not new discoveries claimed here. The addition binds
one actual reader object through the selected callback to both child readers,
and implements their composition with bounded success and failure fixtures.
It excludes the surrounding FullClientBlock header and every other callback.

## Same-reader and row identity

At `0x4fbaec1`, the caller selects callback `0x4e04e90`; at `0x4fbaecd` it
passes its reader in RSI to vector reader `0x5824840`. That function retains
RSI in R15 and callback RDX in R14. Before `call r14` at `0x5824985`, it passes
the same R15 in RSI. The callback retains that reader in R14, calls fixed32
`0x5821430` at `0x4e04ea7`, and passes R14 again at `0x4e04ef1` to blob reader
`0x5824b60` at `0x4e04ef4`. Thus the nested charge/cursor effects concern the
same input object, not merely similarly shaped readers.

Each selected output row is 40 bytes: a 32-byte ID and a nonzero owned-blob
pointer at +0x20 on success. The zero pointer on callback failure is tested by
the vector. The vector releases completed row blobs and its allocation before
returning failure. The source uses `Arc<[u8]>` and a local `Vec` for the same
logical lifetime; native reference-count and allocator layouts are not exposed.
IDs are opaque bytes. No deduplication or sorting occurs in this vector.

## Accounting and failure commits

In limited mode the vector first reads its count (charge 8), reserves `40*N`
with checked multiplication/addition, then refunds 40 immediately before each
attempted row. A row charges 32 for the ID, reads its blob length (charge 8),
then charges the blob length. Successful completion therefore leaves
`initial + 8 + 40*N + sum(blob lengths)`. These are typed charges: small integer
encodings still charge 8. Unlimited mode leaves the counter untouched.

Arithmetic overflow returns failure without storing the overflowing sum.
A representable sum exceeding the limit is stored before failure. A fixed-ID
shortage leaves its cursor unchanged after charging 32. A short blob leaves
its payload unconsumed after consuming the length and committing its charge.
On row failure, reservations for unvisited rows remain; cursor and accounting
are not rolled back. Completed rows do not escape the failed call.

Examples below start at charge zero with a sufficient limit, use one-byte
count/length encodings, and measure cursor consumption from the vector start.

| Input prefix | Consumed | Charged | Outcome |
|---|---:|---:|---|
| Empty | 0 | 8 | Missing count |
| Count 1 only | 1 | 40 | Missing 32-byte ID |
| Count 1, ID, no length | 33 | 48 | Missing length |
| Count 1, ID, length 3, fewer than 3 bytes | 34 | 51 | Short blob |
| Count 2, first ID/length 1/byte, no second ID | 35 | 81 | Second ID missing |
| Same, second ID/length 3, no bytes | 68 | 92 | Second blob missing |

An invalid marker also retains the reused scalar's native fast/slow distinction:
marker 254 with at most eight remaining bytes uses helper `0x58225c0`, consumes
the marker, and records expected_raw=3/found_raw=4; with more than eight bytes,
`0x5821250` records expected_raw=2/found_raw=4 without consuming it. This is an
observed distinction, not a semantic name assigned to the raw error tags.

## Validation and limits

`records.json` retains eight digest-bound windows (563 instructions), 62
selected instruction witnesses, and two relocated helper targets. `verify.py`
checks the full artifact hash/size, enclosing FDEs, instruction bytes and
boundaries, selected facts, and helper bindings. Six negative controls reject a
wrong target, altered reservation, missing refund, altered ID charge, wrong
callback reader, and altered slow-reader error constant. These checks establish
static witnesses; they do not execute the captured target or prove semantics
by themselves.

The source tests independently calculated fixtures for exact and unlimited
budgets, trailing input, duplicate IDs, nested truncation, both invalid-marker
paths, late limit failure, multiplication/addition overflow, and partial-prefix
failure. Debug/release tests, format checking and strict Clippy run on the
source crate. Reproduce with Rust 1.95:

```
cargo +1.95.0 test --offline --manifest-path src/node115-attachment-reader/Cargo.toml
cargo +1.95.0 test --offline --release --manifest-path src/node115-attachment-reader/Cargo.toml
cargo +1.95.0 clippy --offline --manifest-path src/node115-attachment-reader/Cargo.toml --all-targets -- -D warnings
python3 research/work-items/RE-005-node115-attachment-reader-state/verify.py --target artifacts/node/115/hl-node
```

Verifier dependencies: Capstone 5.0.7 and pyelftools 0.32. Premises are the
selected callback, valid reader modes, normal helper returns, and successful
allocation. Physical allocation capacity, OOM/unwind behavior, invalid native
objects, native error/Arc ABI, FullClientBlock header, and end-to-end network
admission remain outside scope. No full-scope component gate changes.
