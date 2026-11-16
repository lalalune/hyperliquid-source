# Digest vote admission: selected conflicts, existing candidates, and per-key capacity

Target: node/115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes. Method: static ELF/FDE and native data-flow inspection. No target execution or emulation.

## Scope and prior boundaries

The expected-reference path needed by #3910 depends on how votes enter the digest tracker before a digest is selected. `RE-017-hash-signature-record-115` lists `0x28b2f10` as an insertion boundary; `RE-017-digest-reference-handoff` leaves admission unresolved. #3271 documents the outer insertion wrapper and #5244 the lookup/watermark path. #7048 establishes the false-to-true selection transition and digest copy; #7049 reconstructs its combined support predicate. Those results are reused. This packet establishes the distinct **pre-insertion admission decision**, including its cross-height, per-key resource count and its ordering relative to an already-present digest candidate.

The source API evaluates a read-only normalized snapshot. It accepts the separately resolved eligibility predicate as an input, since eligibility set construction, history revision identity, signature validity, and native map allocation/mutation are outside this implementation. This is a bounded caller policy, not a complete vote validator or tracker.

## Native decision order

For one present key and incoming height H/digest D, `0x28b2f10` does the following:

1. Resolve eligibility in the key's family. A 20-byte key uses the supplied allowed-key tree; a 32-byte key calls `0x37141b0` through relocation `0x64e6ac0`. Failure returns to the next-key iteration before inspecting or mutating tracker candidates. The source takes this result as an explicit premise, rather than reconstructing the eligibility helper's unresolved input/history provenance.
2. Find H in tracker T+0x18. If that height is selected (raw selector byte +0x20 is zero), compare D against the selected digest at +0x21/+0x31. A mismatch skips this key before looking for an existing candidate. Matching a selected digest does not bypass eligibility.
3. Search that height's digest candidates for D. **If D already exists, go directly to `0x28b3f4d`, bypassing the resource-count scan and threshold.** This does not require that this particular key already supports D. The bypass is candidate existence, not vote duplication.
4. Only for a new candidate, scan all retained height entries and all their digest candidates. For each height, omit its selected digest candidate if it has one; retain other candidates at that height. Count one for each remaining candidate whose support map contains this same incoming key in its same key family. Sum across heights with saturation to U64_MAX.
5. At `0x28b3f40`, compare that total to `0x897` (2199); `ja` skips the key. Totals 0–2199 reach candidate entry/creation; 2200 and above do not. This is a pre-insertion threshold. It is neither 2200 heights, 2200 unique signers, a stake amount, nor an unconditional rejection of a key supporting competing digests.

The source exposes separate reasons for ineligibility, a conflicting selected digest, an existing-candidate admission, new-candidate admission, and capacity rejection. Those explanatory variants are source interface choices, not a reconstruction of a native error union. Count information is computed only on the branch that computes it natively.

## Instruction and container bindings

The input contains optional 32-byte and 20-byte keys. `0x28b2f50` reads the first presence tag; `0x28b2f54` reads the second at +0x21. The first present key becomes raw family 0, while the second becomes family 1. The iterator processes the 32-byte family before the 20-byte family. The checks at `0x28b3148` and `0x28b37e9` select family-specific eligibility and support lookups.

Both tree and flat/wrapped representations are retained in the transcript. Existing-height lookup reaches the same selector and digest before candidate search (`0x28b33b0` / `0x28b340f`). Full digest equality at `0x28b303a`–`0x28b3063` is checked before continuing to `0x28b3419`; inequality falls back to the next-key loop. Existing-candidate tree equality branches at `0x28b34a6`, and flat lookup `0x24c6b60` at `0x28b34e8` returns zero for equality, taking `0x28b34f0` directly to entry acquisition.

The outer scan iterates T+0x18 without filtering on incoming H. The flat path advances by 80 bytes and returns the value at +8 (`0x28b368c`–`0x28b3698`); the tree iterator `0x23874c0` returns the same logical height key/value. Within each height the flat candidate path advances by 96 bytes, with digest at row start and value at +0x20; tree iterator `0x238d1b0` returns its digest/value pair. The selected digest is conditionally remembered at `0x28b36b5`–`0x28b36c2`. Equality with that digest adds zero (`0x28b38af`, `0x28b3a8f`), not a blanket exclusion of the entire selected height.

Support lookup uses candidate value +0x20 for 20-byte keys and value +0 for 32-byte keys. Tree searches compare exactly 20 or 32 bytes. Flat/wrapped helpers `0x24c98a0` and `0x24cbcb0` likewise return zero on a match; `sete` converts a match into one. The inner sum is bounded by the number of candidates, and the outer addition saturates at `0x28b3ef6`–`0x28b3f07`. Normal valid-container invariants are assumed; malformed layout, impossible count overflow, or native panic behavior are not modeled.

After admission, entry acquisition (`0x2db1860` → `0x2421c00`) and digest entry acquisition lead into the insertion/support transition studied by #7048/#7049. This packet does not implement those mutations. An application processing both optional keys must evaluate the second against the state **after** the first key's insertion: an eligible 32-byte key may create D, making D existing for the later 20-byte key even if that family's new-candidate capacity is full. A batch evaluated against one stale snapshot would not preserve this native ordering. The source intentionally offers a one-key, read-only decision API rather than an incorrect batch mutation abstraction.

## Validation and limits

```sh
python3 research/work-items/RE-017-node115-digest-vote-admission/verify.py --target artifacts/node/115/hl-node
cargo test --manifest-path src/node115-digest-vote-admission/Cargo.toml
```

Use Capstone 5.0.7 and pyelftools 0.32 for verification. The verifier checks eight FDE transcripts (2182 instructions), 86 semantic witnesses, the eligibility relocation, the memcmp import, and eight negative controls: wrong target, wrong key-family branch, reversed eligibility, counting the selected digest, charging an existing candidate, rejecting 2199, double-counting a membership, and wrapping the aggregate. These controls validate retained static witnesses, not native runtime behavior.

Source fixtures exercise the 2199/2200/2201 boundary for both key families, candidate existence despite capacity, eligibility and selected-conflict precedence, many candidates at one height versus candidates spread across heights, exclusion of only a height's selected candidate, and independent family counts. The normalized snapshot uses unique height/digest map keys and set membership; it does not infer map normalization or deduplication from arbitrary untrusted native bytes.

Eligibility/history provenance, cryptographic verification, insertion replacement semantics, cleanup/eviction, post-insertion support evaluation, digest selection and emitted certificate ownership remain separate dependencies. No live trusted root or full component-completion claim is made.
