# Raw-root retention joined to later missing-reference behavior

Partial HL115-038 / RE-017, node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This contribution identifies the exact retained raw-key set after `0x5a03fa0` and supplies a stateful witness for a later comparison using the same history. It is not an external trusted-root or checkpoint-replay completion claim.

## Prior evidence and new boundary

[#3807](https://github.com/lalalune/hyperliquid-source/pull/3807) covers mixed-root replacement; [#3826](https://github.com/lalalune/hyperliquid-source/pull/3826), [#3831](https://github.com/lalalune/hyperliquid-source/pull/3831) and [#3833](https://github.com/lalalune/hyperliquid-source/pull/3833) cover cutoff, selection and tree-to-flat machinery. [#4141](https://github.com/lalalune/hyperliquid-source/pull/4141) covers reference lookup and [#4157](https://github.com/lalalune/hyperliquid-source/pull/4157) its local raw-digest origin. Those mechanics and owner identity are reused, not claimed as discoveries here. The new result joins raw retention's exact 50-key effect to a later skipped just-removed reference and a retained mismatch, with duplicate/update and out-of-order insert cases.

## Retention relation

`0x5a07fd3..0x5a07fea` passes context+0x400, its height key and the separately computed raw digest into `0x5a03fa0`. That helper first calls the actual keyed insert/update `0x4dd45c0`. Only the **post-insertion count >=51** enters retention. Seven inlined reverse iterator advances and exactly43 calls to `0x4e2a530` select the 50th-largest unsigned key. The common ordinary iterator retreats by40 bytes per row and switches between the two wrapped slices. It does not select the 51st key or remove the equal cutoff key.

The cutoff is passed to `0x4de5ad0`. Its ordinary branch calls `0x57f2d30`, whose unsigned strict comparisons locate the first key >= cutoff. The source owner retains the smaller prefix temporarily; the returned descriptor owns the >= cutoff tail. `0x5a03fa0` disposes the original prefix and installs that returned descriptor. Exactly the largest50 keys remain when the input was a valid unique-key collection and all delegated operations return normally. A replacement of an existing key does not increase count. Inserting a key smaller than the retained minimum can immediately remove that newly inserted key. Height monotonicity is not assumed.

The companion source owns one logical ordered map and performs that transition. Native flat insertion allocation/growth, physical capacity/head movement, tree traversal, destruction and representation conversion are prerequisites/outside scope; this is not a proof of every physical map implementation. The new source's BTreeMap is independently authored logical storage and is not the captured native tree representation. Digest values are opaque32-byte inputs; the hash computation is credited prior context.

## Later read

The existing reader at `0x5a05cc8` uses context+0x400. Its ordinary lookup `0x5a05df6` skips rows on a missing flag or out-of-range index. A found row locates the 32-byte value at flat row+8, compares both 16-byte halves against incoming row+0x48, and advances by0x68 on equality. A mismatch branches to `0x5a060ec`; this source stops before that diagnostic path. Missing is neither a successful digest comparison nor a mismatch.

The next selector/publication call at `0x5a05fc9` occurs after the comparison loop. The integration witness therefore publishes into a history, then supplies that same owner to a **later** read, with no intervening mutations. It does not claim the digest computed during the current selector call was available to the preceding read. Flag-controlled pruning at `0x5a05ee3`, mixed history and external reference acquisition remain distinct open operations.

## Validation and limits

`python3 research/work-items/RE-017-node115-raw-history-retention/verify.py --target <pinned-node-115>` verifies ten windows / 3,785 bytes / 932 instructions, all43 helper call edges and 25 rejected semantic corruptions. `cargo test --manifest-path src/node115-raw-history-retention/Cargo.toml` (also `--release`) runs five tests: exact inclusive cutoff, duplicate and immediately removed insertion, just-removed skip followed by retained mismatch, every digest byte and ignored incoming bytes, and 8,192 shuffled unsigned-key transitions against a separate sorted-log oracle. `compared` in the fixture counts matching comparisons before the stop; fixture counters are explanatory metadata, not native output fields.

No captured target code is executed or emulated. Full replay correctness, native allocation/conversion, diagnostics, root provenance outside this local owner and component gates remain open.
