# Named wire actions bound to signer admission classes

Target node115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Related #3928; backlog HL115-016. This is a complete92-entry **classification binding**, not complete action authentication or execution.

## Result

The exact serializer spelling `SetGlobalAction` selects validator-only class0. `VoteGlobalAction` selects class1, which tries validator membership and then a chain-selected address list. `ForceIncreaseEpochAction` selects any-signer class2 at this gate; that does not bypass the action handler's separate checks. The92 nominal entries partition into1 validator-only,1 validator-or-listed,38 any-signer,47 known-user-resolution and5 refused actions. All entries appear in [bindings.tsv](bindings.tsv), with index, nominal internal tag, Rust variant spelling, exact wire name and class byte.

The refused spellings are `SystemBoleAction`, `SystemSpotSendAction`, `SystemUsdClassTransferAction`, `SystemApproveBuilderFeeAction` and `SystemSendAssetAction`. Name prefixes do not reliably predict admission: `validatorL1Vote` is class2, `validatorL1Stream` class3, and `agentSendAsset` class3. Matching is case-sensitive; Rust variant names and wire spellings differ.

## Prior credit and precise new work

`RE-010-action-serialize-tag-dispatch-115` already recovers the92 serializer arms, biased selector and wire names across six copies. `RE-010-action-msgpack-number-identifier-115` separately treats numeric identifier decoding. `staking-admission-gate-115` recovers the raw admission table and two gates but explicitly leaves its indices unbound to wire names. This packet composes those facts into a native-rebound, source-usable mapping, verifies all552 serializer/name/class joins and checks the previously excluded third gate without confusing its owner layout. It does not claim those separate primitives as new discoveries. The recent92-arm dispatch work in #5400 concerns other dispatch tables; #5398 concerns21 typed-data builders, not this admission join.

## Native binding and domain

The getter `0x36c2030..0x36c204e` reads a64-bit in-memory word, subtracts0x86, and uses index20 when the unsigned subtraction borrows. Otherwise it uses word-0x86. It reads one class byte from `0x79dd60`. The six serializer copies use the same biased expression and signed relative dispatch tables:

| Function |92-entry table|
|---|---|
|0x2bce570|0x60974c|
|0x36aef70|0x799dec|
|0x36b3f80|0x79a0cc|
|0x4d84400|0x914824|
|0x4d86d80|0x914994|
|0x4d89700|0x914b04|

For every index, the relative table entry selects an arm that constructs four pointer-length pairs: enum `Action`, Rust variant spelling, tag key `type`, and exact wire spelling. `bindings.json` retains each arm and every pointer/store/length/string address. The original ELF is independently decoded again by `check_join.py`, including pointer-length adjacency; every observed row must match the owned Rust table and the TSV. No prior packet's extracted row is trusted as native evidence without rebinding.

Nominal words are0x86..0xe1. **All** smaller64-bit words select index20 (`VoteGlobalAction`) in the recovered getter and serializers. This is a many-to-one internal selector alias, not evidence that every such word constitutes a valid Action payload or that those numbers are accepted wire discriminants. Above0xe1 the getter/serializers have no upper guard in these functions; the owned API reports `OutsideRecoveredDomain` instead of reproducing an unchecked read. Catalogue indices, nominal in-memory tags and wire strings are distinct input domains.

## Third gate and routing meaning

Both `0x4d907c0` and `0x4d909b0` call slot `0x64e7860 -> 0x36c2030`. The third gate dispatches class0/1 to the same arm and class2/3/4 to any-signer, known-user helper, and refusal arms respectively. Its relative table `0x914ea8` points to `0x4d909fe`, `0x4d90a7a`, `0x4d90a3c`, `0x4d90a94`.

At `0x4d909fe..0x4d90a18`, class0/1 invokes `0x64e4e38 -> 0x36c8430`, passing **Exchange+0x4a78** and the full20-byte signer. Membership success preserves signer with0x1a2; failure in class0 reaches0x7f. Class1's odd low bit enables the address-list fallback. Raw selector3 chooses one list, other values the other; no network name is inferred. Class2 reaches0x1a2 directly. Class3 calls `0x55feb90` and propagates its result/resolved identity; this packet does not implement that helper. Class4 produces0x81. The two older gate copies use +0x3f08, so their owner offsets are not silently reused for this third copy. The primary helper/list/crypto implementations remain dependencies; an enum class is never an authorization verdict.

## Owned API and validation

`src/node115-action-admission-binding` supplies exact wire-name lookup, bounded catalogue-index lookup and the biased internal selector with explicit alias metadata. It does not serialize/decode payloads, recover a signer, decide membership, initialize address lists, resolve a user or execute an action. No boolean stand-ins for these dependencies are supplied.

```
python3 research/work-items/RE-017-node115-action-admission-binding/verify.py
python3 research/work-items/RE-017-node115-action-admission-binding/check_join.py
cargo +1.95.0 test --offline --manifest-path src/node115-action-admission-binding/Cargo.toml
cargo +1.95.0 test --offline --release --manifest-path src/node115-action-admission-binding/Cargo.toml
cargo +1.95.0 clippy --offline --all-targets --manifest-path src/node115-action-admission-binding/Cargo.toml -- -D warnings
```

Use Capstone5.0.7. Static verification authenticates the original target, FDE boundaries,10 instruction windows, all relative/string/class bindings and81 deliberately corrupted facts. The corruption phase bypasses global/window hashes after authenticating the target, requiring fact checks to reject changes. Join checks independently reject class, source spelling and arm substitutions. Rust tests exercise critical named policies, every below-base word, out-of-domain64-bit values, exact spelling, all92 unique nominal entries and class counts. These checks are static and synthetic, not native runtime-equivalence measurements. No captured target instructions are executed or emulated. Full staking and ABCI component gates remain false.
