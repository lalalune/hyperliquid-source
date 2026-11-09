# Node #115 nonzero-d8 order removal continuation

Backlog HL115-041. Target `hl-node` release115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Addresses are ELF virtual addresses. Original static disassembly only; no target
execution/emulation. Full component gates remain false.

## Prior boundary

Merged #3672 owns the unlink prefix, including slab/free-list, event, external
quantity and cached-head writes. Its independently authored standalone module
`src/node115-book-order-unlink/lib.rs` returns `End::SideCall` for a nonzero
original element+0xd8 byte, before calling `0x4de02d0`. This contribution reuses
that exact module in an integration test rather than copying or replacing its
implementation. Related #4868/#4870 own different book-location call edges.

## Recovered continuation

The four call sites `0x58e1a8c`, `0x58e25cc`, `0x58e3174`, `0x58e3db4` forward a
candidate level pointer as the stack argument to the two unlink owners
`0x58dfbc0` / `0x58dff20`. The prefix checks that pointer and the signed field
before arriving at this continuation. Within each owner, the same supplied pointer is used for the cached-head
update, map at +0x50 and totals. The upstream lookup and ownership of that
pointer are not newly established.

Both owners copy the saved element+0xf0 u64 and +0xdc u32 into a 12-byte search
key. They pass `level+0x50` and that key to `0x4de02d0` only when the original
+d8 byte is nonzero (not just equal to one). That helper removes one exact-key
entry. Flat rows are 24 bytes with the value at +16; tree search separately
compares the u32 and u64 key lanes, so equality requires both lanes. The helper
returns an optional removed value. Both owners ignore it.

For flat storage, the helper shifts the shorter side of the ring and decrements
its length after a hit; a miss leaves its contents alone. For tree storage it
calls the exact-key search/removal wrapper, then flattens when the resulting
length is at most31. This threshold is applied even if lookup missed. The
underlying tree balancing, ring copy and tree-to-flat materialization helpers
are retained as structural premises, not reconstructed byte-for-byte here.

After the call, without testing its result, the owners update:

* `level+0x70 = saturating_sub(old_level_quantity, saved_element+0xe0)`;
* `level+0x78 = saturating_sub(old_level_count, 1)`.

These writes occur even on an absent key. They are distinct from the slab count
and external quantity writes already made by #3672. A missing key is therefore
not a reason to skip these level updates or to repeat the prefix. Later linked
order processing is unchanged and remains outside this continuation.

## Owned implementation and integration

`src/node115-order-unlink-level` consumes the existing `SideCall` result and an
owned logical level map. Keys retain both raw lanes; values are opaque u64s.
It returns a removal observation for testing, records the flat/tree choice and
performs the two level-total writes. Rust BTreeMap is an independent logical
container, not the native physical ABI. Valid unique-key collections, successful
structural helper operations and a saved original quantity are premises.

The integration witness calls the actual existing unlink module on a 272-byte
source-owned element. It checks the prefix has already updated the slab and
external total while leaving +70/+78 unchanged at its SideCall stop. Resuming
removes only the exact matching pair and updates both totals. Other tests cover
misses, saturation, a non-one nonzero+d8 byte, retained counts31/32/33/64/65,
and stopping without writes for non-SideCall outcomes.

## Reproduction

```
python3 research/work-items/RE-006-node115-order-unlink-level/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-order-unlink-level/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-order-unlink-level/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-order-unlink-level/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-order-unlink-level/Cargo.toml --all-targets -- -D warnings
```

Use Python with Capstone5.0.7. Twelve Rust tests comprise eight unchanged prior
prefix tests and four new continuation tests. The verifier checks nine windows,
790instructions,800facts and21semantic corruption controls, authenticating the
whole target and FDEs first. Those counts are static evidence, not runtime
comparisons. Exact repository check outcomes are reported in the PR.

Allocator failure, malformed structures, native tree layout, full linked-order
continuation and complete cancellation atomicity are unclosed. No unlicensed
inferred source was used. This packet and new Rust are independently authored.
