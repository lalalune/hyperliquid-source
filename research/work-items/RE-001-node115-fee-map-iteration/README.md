# Node #115 fee-map iteration and selected sum

Backlog HL115-057. Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; all addresses are ELF virtual addresses. No target instructions were executed or emulated.

Merged #2176 traced validator `0x36a1c20`'s post-gate sum but left its constructor and iterator opaque. This bounded successor joins `0x3c6d100`, `0x4504fe0`, `0x37c7260` and the validator's consumer. The earlier ordering, range, finiteness and floor-helper results remain prior work; full fee validation is not claimed.

The constructor transforms the flat descriptor into a tag-2 iterator of up to two ranges of 32-byte rows. Its next function advances the first range before the second, returns a row pointer and a value pointer at row+24. The non-flat path delegates to a tree iterator. Its result points to the 20-byte key at node+0x60+20*i and the 8-byte value at node+8+8*i; navigation visits entries in the tree's child/key order. The validator constructs this iterator and adds each pointed-to f64 in visitation order, starting with the pinned negative-zero literal, then rejects a sum strictly above the pinned 1.0 literal.

`src/node115-fee-map-iteration` models a valid wrapped ring and a logical ordered tree, preserving every supplied row and performing the selected IEEE-754 fold. Its tree shape is a premise, not a physical native B-tree implementation. Key uniqueness, actual construction and allocation, malformed structures, exact economic identity, floor-helper behavior, and full validator acceptance remain open. The isolated post-gate comparison treats an unordered NaN as not greater, reflecting the instruction condition only; it does not claim NaN passes earlier validation. Duplicate rows are preserved if supplied, not asserted reachable from a valid map.

Four tests cover wrapped order, tree traversal, empty/exact boundary and an order-sensitive nonnegative floating-point witness. The static verifier authenticates the target and enclosing FDEs and checks five windows (909 bytes, 225 instructions), 32 facts and nine semantic mutations. These are static checks, not a target execution comparison. Run with Python and Capstone 5.0.7:

```sh
python3 research/work-items/RE-001-node115-fee-map-iteration/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-fee-map-iteration/Cargo.toml
```

Project-authored source and evidence are MIT. No completion gate changes.
