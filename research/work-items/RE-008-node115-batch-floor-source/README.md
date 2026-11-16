# Consensus batch collection and round-floor source

Target `node/115`: SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. All target evidence was obtained statically; no target execution or emulation was used.

## Scope and reuse

This supplies logical Rust source for the existing block-batch and round-floor contracts, plus a concrete caller connection from the collected output to the floor consumer. It advances the RE-008 validation path. Existing `RE-008-block-batch-filter-115` already owns the static interpretation of `0x2705af0` and ring search `0x24c5ba0`; `RE-008-round-floor-115` already owns `0x231b6f0` and `0x294acb0`. These are credited inputs, not newly discovered helper semantics. Their outcome/stub tables are analytical fixtures, not native executions.

The remaining implementation scope is ordered collection, known-block elision, the distinct batch and floor round projections, exact hash lookup in both map representations, and the optional minimum over resolvable outputs. Signed-block verification remains the established `0x2786870` boundary. This crate does not duplicate the unmerged variant-zero serialization in PR #7059 or claim to perform cryptographic verification.

## Batch contract

`0x231b6f0` passes an iterator and its original backing pointer as the output write cursor to `0x2705af0`. The latter reads one `0x1b0`-byte record at a time, advances the iterator before processing, and emits at most one record. Normal emitted records preserve input order. The driver computes output length from the final write cursor, resets the consumed iterator fields, and returns the original backing allocation. The Rust model reconstructs the logical result, not that allocation reuse or cleanup machinery.

Each input contains a block, certificate vector and 32-byte hash. The closure's first owner has a known-block map at `+0x208` and a threshold at `+0x2c8`:

1. An already-known hash elides the block and retains the certificate/hash output, unless the certificate capacity word is the native `0x8000000000000000` sentinel. An empty certificate vector is not this sentinel.
2. For an unknown hash, select `block+0x50` when `block+0x18 == 0x8000000000000001`; otherwise select `block+0xa0`. Saturate its unsigned increment at u64::MAX. If the result is below the threshold, drop this record. Equality passes.
3. Recheck the known hash. A newly found hash at this second lookup drops the record, unlike the first lookup's elision. The source explicitly requires a stable known-map snapshot, under which this recheck cannot change the outcome; it does not claim native locking or immutability.
4. Call `0x2786870`. Its normal success copies the original `0x178`-byte block unchanged; error takes the sentinel arm. An error emits nothing. On success the certificate capacity sentinel still suppresses emission, so verification occurs even if that sentinel later prevents output.

The wrapper obtains a provider through slot `0x64e64b0 -> 0x595e5c0`, invokes signed admission through `0x64e64b8 -> 0x57e8bd0`, then the structural check through `0x64e64c0 -> 0x59d6b80`. These helpers are dependencies, not replaced with invented semantics. The source's supplied predicate represents this boundary under normal valid-input premises; it cannot replace the retained block. Panic/unwind, native niche collisions on malformed blocks, refcounts and deallocation are outside the model.

## Floor contract and actual output consumer

`0x294acb0` scans `0x1b0`-byte output records. Inline blocks are used directly. For an elided block, it resolves the full hash in the supplied known map (tree or sorted wrapped ring); an absent hash leaves the running minimum unchanged.

For a resolved block B, round selection is deliberately different from the batch gate:

- `B+0x18 == MIN+1`: use `B+0x50`.
- Otherwise, `B+0xa8 == MIN+1`: use `B+0x48`.
- Otherwise: use `B+0xd8`.

The accumulator is an unsigned minimum, not a maximum or saturating increment. The wrapped ring uses `0x198`-byte rows with the 32-byte hash first and block at `+0x20`; sorted unique keys and valid geometry are input premises. Source constructors check these as host-interface guards, not recovered native validation behavior.

The actual common caller is `0x2e098e0`. At `0x2e0a4dd..0x2e0a56e`, it builds the collection closure with owner `H+0xb8` and wrapper context `H+0x788`. Hence the batch's known map is `(H+0xb8)+0x208 = H+0x2c0`, and its threshold is `H+0x380`. The returned vector at stack `+0x9d8` is copied to `+0x9a0`; its data pointer and length produce `R15` and end pointer `R13` at `0x2e0bbe5..0x2e0bbf9`.

At `0x2e0be17`, the floor consumer selects the same `H+0x2c0` known-map address. It skips unresolved elided outputs until finding the first inline or mapped block. For that first resolved output it stores the next-record pointer, end pointer and map in stack `+0x50/+0x58/+0x60`, selects the initial round, and calls `0x294acb0` on the suffix at `0x2e0c2bd`. No resolved block produces option tag 0 at `0x2e0bfdb`; a resolved minimum produces option tag 1 plus the value at `0x2e0c2ca/0x2e0c2d6`. Thus an empty/all-unresolved batch is distinct from a real round zero or u64::MAX.

This establishes output and map identity on the selected path. Intervening calls are retained as boundaries: no claim is made that native map contents cannot change between collection and the later scan. Each source operation takes its own explicit map input. The rest of the large caller, protocol outcomes and consensus authority are not reconstructed here.

## Reproduction and source checks

`records.json` retains five full FDEs and four bounded caller windows: nine windows, 1,052 instructions, 220 witnesses, three relocations and two import bindings. `verify.py` checks the pinned artifact, exact bytes, complete instruction transcription within each window, FDE bounds and selected relations, and rejects 15 negative controls. These controls include wrong record stride, known-block verification, wrapping the increment, rejecting equality, conflating the two round projections, taking a maximum, truncating hashes and treating absent floor as present zero.

Run the packet's reproduction entry and the crate's debug/release tests, formatting and strict Clippy. Source tests exercise ordering, gating, sentinel versus empty payload, call counts, wraparound lookup, missing hashes, distinct projections and saturating boundaries. An independent table/linear oracle checks the resulting batch and optional minimum. Packaging records exact source/evidence hashes and the repository static checks. No test executes the captured target.
