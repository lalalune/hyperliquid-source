# Selected TWAP success-record cleanup

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; repository base `a8616af9432b8d8517b2af677880e117b7c28ef3`. This is a partial RE-010 continuation of #2202 and #3268. The earlier packet closes only the empty-error route; #5985 calls `0x2419810` but explicitly leaves that body unmodelled. This contribution studies the successful TWAP-produced tag-4 record in both route-specific flushers, not all events or an outer transaction. The captured program was never executed or emulated.

`0x2c2f020` builds tag 4 on both successful routes, copies a 696-byte record on the perpetual route and a 712-byte record on the spot route, and places `0x8000000000000001` at record offset `+0x80`. The first `0x78` payload bytes originate in an earlier helper result; field meanings are not inferred. The producer supplies an initial vector of one record. Later callers may supply longer valid same-variant vectors; their production is not asserted.

Both flush entries detach the vector descriptor before checking its length: they replace its three words with `(0, 8, 0)`, then iterate the original storage at strides 696 and 712. Empty input skips the body. For a valid tag-4 record, the decoded jump-table entries `0x5ec98c+8` and `0x5ec9d0+8` land at `0x2419a27` and `0x241a642`. The selected normal continuations forward a tag-4 copy to `0x282c3a0` or `0x282bee0`, respectively; their tag-4 table entries land at `0x282c4dc` or `0x282c01c`.

Both selected consumer arms read record qword `+0x18` and, if nonzero, call the allocator free slot with pointer `+0x20` and that qword as the byte count. They then read qword `+0x80`; negative or zero values skip a second free. The producer's `0x8000000000000001` sentinel is negative and takes that skip. These tag-4 consumer arms do not use the owner arguments passed to them; this does not establish effects of earlier helper calls, other tags, or surrounding transaction semantics. The selected downstream arm is cleanup, not evidence of an order-book or ledger update.

`src/node115-twap-tag4-cleanup` provides a source-owned projection for already-constructed, valid, distinct allocations: `std::mem::take` detaches a logical queue; a nonempty owned allocation is actually dropped in record order; the explicit second-descriptor sentinel contributes no free. `Box<[u8]>` makes allocation length equal to its size, a source-domain premise for the observed free arguments. The result reports release sizes for tests, not native diagnostics. Native addresses, unused bytes, physical descriptor representation, allocator failure, panics/unwind, full event production, opaque earlier helpers and transaction commit/rollback are outside scope. A perpetual-route clearinghouse-index bounds check must succeed before the downstream consumer.

The packet binds 14 instruction windows (1,535 bytes, 267 instructions), 98 facts and 37 rejected changed-byte controls. The producer, detach loops, all four tag-4 table entries and the selected two cleanup arms are pinned to the full digest. Rust tests exercise both routes, empty input, record-order preservation and 256 ownership combinations; they verify the projection, not runtime equivalence. All component and backlog full-scope gates remain open.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-010-node115-twap-tag4-cleanup/verify.py --target /path/to/original/hl-node
cargo test --offline --manifest-path src/node115-twap-tag4-cleanup/Cargo.toml
cargo test --offline --release --manifest-path src/node115-twap-tag4-cleanup/Cargo.toml
```
