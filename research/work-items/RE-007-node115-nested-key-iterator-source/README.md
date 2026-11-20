# Nested key iterator consumed by the node 115 collectors

The Rust crate `src/node115-oracle-nested-keys` implements the address and key stream that two collectors materialize. It exposes the size hint at any point in the walk. Before this change [PR #6045](https://github.com/lalalune/hyperliquid-source/pull/6045) and [its research packet](../RE-007-oracle-nested-map-115/README.md) specified the two walkers, progression through their map representations and size arithmetic. This contribution supplies a reusable typed Rust iterator and traces the concrete consumers that use its lower bound for reservation.

Target `artifacts/node/115/hl-node` has 105896032 bytes and SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Coordinates are image VAs. Reused instructions are stored as cited context.

## Iteration contract

Each phase drains the currently active inner iterator, visits each remaining outer entry and drains its children, then drains a separate supplemental iterator with its own saved 20-byte outer address. The first phase exhausts before the second starts. Native outer ring rows have stride `0x38`. The two phases use inner ring strides `0x60` and `0x70`. Tree representations call their own iterator helpers. Host `BTreeMap` and `VecDeque` preserve the corresponding logical tree or split-ring iteration order. Inputs describe live, valid maps with unique ordered keys. Only the projected address and u64 key are read by the consumer. Equal inner keys belonging to different outer entries or phases remain distinct emissions.

`5ab8240` and `5ab8bd0` return native tag 1 with address at out+8 and key at out+20 (hexadecimal offsets). Both phases use the same success tag. Tag 0 indicates exhaustion. The supplemental address is at iterator+f0 or +1f8, distinct from the active address at +90 or +198. The Rust iterator represents the native tag with `Option<KeyPair>`.

`5ab9560` computes the lower bound from the remaining current and supplemental rows with unsigned saturation. As long as any outer entry remains, the upper bound is unknown, including when every remaining child collection happens to be empty. Once no outer entries remain, the checked sum provides the upper bound. A finished phase contributes `(0, Some(0))`. The two bounds compose across phases using saturating addition below and checked addition above. The source computes the hint without inspecting any future inner collection.

`5b798ec` calls the first walker, checks for tag 1 and invokes `5ab9560` on the same iterator at `5b79900`. It uses the lower bound plus one for the first reservation with a minimum of four rows. On later growth it invokes the same hint at `5b79a30`. The second collector pairs `5ab8bd0` and `5ab9560` at `5b86b0c` and `5b86b20`. Consumers can use the Rust stream directly or collect it. Native allocation geometry, raw pointer lifetimes, non-key value fields, economic interpretation, and the prior packet's separate filtered walkers are outside this key-projection contract.

## Reproduction

```sh
python3 research/work-items/RE-007-node115-nested-key-iterator-source/verify.py --target artifacts/node/115/hl-node
cargo test --manifest-path src/node115-oracle-nested-keys/Cargo.toml
```

Use Capstone 5.0.7 and pyelftools. The verifier checks the target identity, FDE bounds and 1,608 instructions across the prior walker bodies and selected caller windows. The independent Rust fixtures compare a manually specified sequence and bounds before each poll, including transitions from an unknown upper bound to an exact upper bound. Tests cover tree and physically wrapped deque inputs, empty outer children, duplicate inner keys across addresses, saved active and supplemental rows, differing value types, and repeated end-of-stream polls. The native artifact was parsed statically. Existing component gates and the prior packet's sample counts are unchanged.
