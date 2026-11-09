# Node #115 staking nested-row reduction and projection

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The prior projection packet, merged #2219, established the caller's lookup, nested descriptor, metadata copies and append handoff but explicitly left its reducer opaque. #3869 bound an additional source-location argument without assigning behavior. This packet closes the reducer's value operation and composes it with the previously observed projection. It does not claim snapshot membership, identity names or original public ABI.

In `0x4351de0`, a tag-2 iterator traverses up to two 32-byte-stride spans. For each yielded non-null row it adds the u64 at row+24 to a zero-initialized accumulator. Unsigned carry selects `u64::MAX`. The alternate representation calls `0x37c4430` and adds the u64 behind its returned value pointer using the same saturation; its physical traversal remains a premise. An empty iterator returns zero. Duplicate values are each added; there is no deduplication in this reducer. A valid iterator and readable row pointers are prerequisites.

The predecessor #2219 binds the two source metadata copies to row+0x40 and row+0x54 and the local append record beginning at stack+0xf8; this packet reuses those established caller observations. The caller `0x36c7b30` prepares a tag-2 descriptor with 32-byte scaling, passes it to the reducer and stores the returned word in its 48-byte local record. It copies two distinct 20-byte metadata fields following the word, then hands the record to `0x3901070`. That helper's allocation and failure behavior remains outside this model. Source field names, economic units, the metadata identities, tree traversal correctness, and the no-iteration output accumulator's representation remain open. No component gate changes.

`src/node115-staking-projection` independently models the observed reduction and logical record. It accepts yielded rows rather than inventing tree or allocator semantics, decodes the value at byte 24, and encodes the observed 48-byte local record. A 216-case u128 oracle tests the saturation boundary. The 24 opaque bytes are retained as input but do not affect the reduction. This is a projection contract, not a byte-equivalence or node-completion claim.

`records.json` retains two selected windows (551 bytes, 129 decoded instructions), facts and seven semantic corruption controls. `verify.py` authenticates the complete target SHA-256 and enclosing FDE boundaries, reproduces instruction rows and checks control mutations. These are static evidence and control results, not runtime comparisons. Native bytes were not executed or emulated. Use Capstone 5.0.7 and the pinned target:

```sh
python3 research/work-items/RE-001-node115-staking-reduction/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-staking-projection/Cargo.toml
```

MIT project-authored code; no unlicensed inferred source copied.
