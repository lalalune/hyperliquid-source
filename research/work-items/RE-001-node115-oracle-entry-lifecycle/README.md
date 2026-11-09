# Node #115 selected oracle entry lifecycle in flat storage

Partial HL115-054, pinned to Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Prior [#2141](https://github.com/lalalune/hyperliquid-source/pull/2141) establishes the ratio/threshold decision and local timestamp writes while leaving the container helpers opaque. This follows the two concrete selected keys through the flat entry, insertion and removal paths. It does not duplicate that decision, name timestamps as a particular unit, or claim the complete oracle.

## Keys and selected entry

The two original caller sites pass selector 1 and selector 0 at `0x538141e` and `0x5381496`. The stateful and reset paths form key bytes `[0, selector]` and address the same owner member +0x78. Flat search `0x45511c0` and tree search `0x35bf930` compare the variant first and, on variant zero, its second byte. This source bounds selected variant-zero keys to the two observed values; other valid variant-one rows may be preseeded with their word/byte comparison fields. It does not claim all other key encodings or their constructors.

On the stateful branch `0x3cc83c0` locates the entry, then `0x3f15c10` returns an occupied value or inserts a vacant value. New-entry staging supplies binary64 10.0 and zero dword markers at value+8 and +20. It does not initialize every staging byte: the caller then writes the complete incoming 12-byte record to first+8 because the zero marker selects that store, and always writes it to latest+20, so the selected normal post-write value is fully modeled. For an occupied value, only the low dword at first+8 controls whether the first 12-byte field is replaced; the latest 12-byte field is always replaced. Existing threshold bits remain intact. The source stops before duration conversion and the code-8 diagnostic.

## Flat insertion and removal

On a valid ordinary ring with spare capacity, `0x4548aa0` inserts the 48-byte key/value row at the search index. It compares suffix count `length-index` with prefix count `index`: a tie or longer suffix moves the prefix and decrements head; a shorter suffix moves the suffix. The move helper `0x457b890` operates on 48-byte rows. On the selected reset branch `0x3ce7650` removes a found entry and decrements length; it compares `length-1-index` against `index`, moving the prefix and incrementing head on equality or a longer suffix, otherwise moving the suffix. A miss leaves the logical rows unchanged. For this selected variant-zero key set, the provided source allows already-valid variant-one rows so index-1 insertion/removal really moves an existing row. It preserves all existing logical values.

Valid ordered unique active rows, no interfering writes, normal allocation and helper returns are premises. Full storage stops before native grow. Tree search, insertion, balancing, shrink/conversion, raw inactive slot bytes, allocator failures and unwind are outside the owned flat model. The ratio gate and its code-8 threshold remain credited prior behavior, not supplied as a new native decision.

## Validation

`python3 research/work-items/RE-001-node115-oracle-entry-lifecycle/verify.py` authenticates the target, 11 selected windows (4,811 bytes / 1,239 instructions), call bindings and 32 semantic corruption controls. No captured instruction executes or is emulated. Six Rust tests pass in debug and release: every head across capacities 2..12 for both selected insertion orders; preexisting variant-one rows exercise an actual prefix move and restore, arbitrary occupied threshold bits survive, low-dword zero repeats initialization, and a full ring stops before growth. Run `cargo test --manifest-path src/node115-oracle-entry-lifecycle/Cargo.toml` and the same command with `--release`.
