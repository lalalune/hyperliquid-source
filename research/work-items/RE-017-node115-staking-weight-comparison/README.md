# Node #115 selected-weight threshold in staking comparison

Backlog HL115-068. Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
ELF virtual addresses, original static analysis; no target execution/emulation.

## Question and prior boundary

Merged #2281 recovers the outer `0x36c7f70` lookup/materialization/cleanup chain
but stops at comparator `0x422e0f0`. The name "comparison" does not establish
structural equality or set ordering. Open #4362 and merged #2750 already establish the strict two-thirds arithmetic in a distinct 20-byte-key family with saturating folds. This contribution focuses on this 32-byte-key owner binding and checked folds, and closes the helper's actual
weighted relation and its selected-key lookup fold, without inferring signer
identity or authorization from the 32-byte layout.

## Observed contract

`0x4351520` consumes keys from the first iterator through `0x37c9490`. It reads
the associated map pointer at iterator+0x48. Each key is compared over all32
bytes against the weighted map (40-byte flat rows, value at+32; the tree branch
uses the same full32-byte comparison). Missing keys contribute nothing. Matched
u64 values are added with checked arithmetic: carry returns failure, not a
saturated total. It does not deduplicate successive key yields itself.

`0x422e0f0` saves that fold result, copies the second iterator, and independently
adds its yielded 40-byte row+32 values. In the tag2 route it walks both wrapped
spans. The alternate route uses `0x37cb190`'s value pointer. A carry in this total
fold returns false. A failed selected fold also returns false after the total
fold. On two successful sums it compares the full-width products:

```
3 * selected_weight > 2 * total_weight
```

The total is doubled with its high carry bit retained; selected is multiplied
by3 with the x86 high product. The final strict unsigned comparison therefore
does not overflow64bits or accept equality. Empty/zero populations return false.
The operation is neither row-count quorum nor equality of the two key lists.

The outer owner binds both observations to its materialized map at stack+0:
first iterator+0x48 is set to that map; the second descriptor is separately
built from the same map's current representation and length. This establishes
local object identity. It does not prove the materializer's semantic weighting,
concurrent snapshot guarantees, authentication, or validity of every upstream
state. `0x3bcb550` and physical iterator/search invariants remain prerequisites.

## Source and validation

`src/node115-staking-weight-comparison` performs real key lookups in an owned
logical map and checked folds. It accepts key yields without introducing a
hidden deduplication policy. Valid native collection traversal is a premise;
tests of repeated supplied yields describe the helper's conditional behavior,
not a claim that a valid source collection contains duplicate keys. Its raw-row
decoder binds all32key bytes and the little-endian word at+32.

Five tests distinguish equal-threshold refusal, highly unequal weights versus
row counts, missing keys, zero populations, overflow refusal, 128-bit products
and exact key bytes. An independent floor-division oracle checks all5,832
combinations of three weights0..8 and eight selection masks. Native assembly
is never run; these source tests do not alone establish target equivalence.

```
python3 research/work-items/RE-017-node115-staking-weight-comparison/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-staking-weight-comparison/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-staking-weight-comparison/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-staking-weight-comparison/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-staking-weight-comparison/Cargo.toml --all-targets -- -D warnings
```

Capstone5.0.7 required. The verifier authenticates the target digest, FDEs and
five selected windows:761instructions,767facts,18semantic corruption controls.
It checks changed key width, weight/reference fields, overflow branches, ratio
constant, strictness and call targets. The corruption checks bypass blanket
window hashes only after authenticating the original file. Repository check
results and exact environment commands are in the PR.

The materializer, physical B-tree layout, authenticated membership, complete
force-epoch handler and outer state mutation remain open. This is a bounded
comparison contract with all full-component gates false. Newly authored code
and evidence are MIT; no unlicensed inferred source was copied.
