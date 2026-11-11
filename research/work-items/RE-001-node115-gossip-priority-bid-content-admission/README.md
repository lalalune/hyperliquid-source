# RE-001: node #115 GossipPriorityBid Content admission

- Component: action deserialization; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Complete visitor `0x2058c40..0x20599a6` and seven helper-context FDEs, with exclusive ELF virtual-address bounds in `records.json`. All full-scope gates remain false.

## Finding

The visitor consumes Serde's already-decoded `Content` representation. Its pinned type descriptor says `struct GossipPriorityBidAction with 3 elements`. It accepts raw Content tag20 as a sequence and tag21 as a map. This evidence concerns that visitor, not a direct JSON/MessagePack byte reader or proof of external endpoint reachability.

The previously open question has an asymmetric answer: **a sequence must contain exactly three elements, even when `maxGas` is absent in meaning**. A map may omit `maxGas` and obtain `None`; a sequence must supply its third position with an explicit option-compatible value.

| Decoded Content | Result after valid earlier fields |
| --- | --- |
| Map: slotId and ip | success, maxGas=None |
| Sequence: slotId, ip | invalid length2 |
| Sequence: slotId, ip, None | success |
| Sequence: slotId, ip, unsigned integer | success, maxGas=Some(integer) |
| Sequence: three valid fields plus any extra | invalid length, after decoding the first three |

Sequence elements are decoded in slotId/ip/maxGas order. Missing element0,1 or2 returns the corresponding invalid-length error. A scalar or string error stops before later elements and before the excess-length check. For example, an invalid first value in a four-element sequence reports the first value error, not length4. After three valid values, any length other than3 is rejected. Allocation/drop/error formatting remain opaque; the report does not imply rollback of a byte cursor.

Map string and byte keys match exactly `slotId`, `ip`, `maxGas`. Only the Content u8 and u64 variants additionally admit numeric field indices0,1,2. The pinned jump table rejects other numeric Content types as field identifiers, even if their value is0..2; unknown spellings/indices are rejected, not skipped. The byte-key helper checks all characters and lengths. There are no case-folded or snake_case aliases in this visitor.

The already-known named map schema and duplicate rule are bound to #115 as context: slotId and ip are required; maxGas is optional. Duplicate detection occurs before decoding the duplicate value. The option's unseen state2 is distinct from an explicitly decoded None state0, so a second maxGas is a duplicate even when the first was None. At map exhaustion, missing slotId is checked before missing ip, then an unseen maxGas becomes None. An earlier key/value error wins over these completion checks. Ordered pairs are modeled directly so duplicate keys are not erased by a host-language dictionary.

The integer helper context accepts Content unsigned integer variants and nonnegative signed variants, not booleans/floats/numeric strings. The maxGas option helper recognizes None tag16 and Unit tag18, explicit Some tag17 and a direct integer; its bound newtype forwarding paths are recorded. The IP field uses a string helper; this visitor does not parse IPv4 or enforce the later priority-bid handler's business gates. UTF8 byte-string conversion, allocation failures and exact error text are helper boundaries. Relations validate owned/borrowed string inputs and explicit invalid-type cases, rather than claiming the byte-string helper's full internals.

Success output retains maxGas option tag/value at +0/+8, the string descriptor at +0x10/+0x18/+0x20 and slotId at +0x28. The raw error marker is2. Payload bytes belonging to an inactive option/error variant are not claimed initialized.

## Validation and limits

The eight complete FDEs bind caller ordering, option-state distinction, key dispatch, scalar helper calls, result layout and error branches. Operand-driven relations enumerate sequence lengths and earlier-error combinations, ordered map key/duplicate combinations with invalid values, supported field aliases and option boundaries. Four actual changed instruction operands distinguish arity3, numeric maxGas index2, explicit None and unseen/duplicate state. Semantic comparison is static and does not execute or emulate the target.

This closes the combined Content-level schema and first-error policy for this monomorphized visitor. It does not claim all other deserializer instantiations, external transport routing, malformed-byte cursor behavior, IP parsing or reservation/debit semantics. Helper bodies are authenticated context, not separately claimed generic discoveries.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-gossip-priority-bid-content-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-gossip-priority-bid-content-admission/verify.py --controls
python3 research/work-items/RE-001-node115-gossip-priority-bid-content-admission/relations.py
python3 -m unittest discover -s tests -p 'test_node115_gossip_priority_bid_content_admission.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-gossip-priority-bid-content-admission/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

[PR #2008](https://github.com/lalalune/hyperliquid-source/pull/2008) already establishes the older-release map names, required fields, optional maxGas default and duplicate rejection. It expressly leaves the sequence/array arm unproved and asks whether two elements can omit maxGas. This packet answers that question against node115 and adds the combined positional/numeric-key/error-order boundary; it does not re-claim those named map rules as new.

[#2854](https://github.com/lalalune/hyperliquid-source/pull/2854) owns node115 wrapper admission, IPv4 parsing and reservation/debit effects while excluding external wire decoding. [#2079](https://github.com/lalalune/hyperliquid-source/pull/2079) and [#393](https://github.com/lalalune/hyperliquid-source/pull/393) supply dispatch context. No full byte-codec or handler-equivalence claim is made here.

GPT-6.1 Terra searched all-state PR metadata and available file evidence; inaccessible historical material and missing patches limit an absolute uniqueness guarantee. New analysis and relations are independently authored under MIT; evidence/export scaffolding reuses existing MIT packets. No unlicensed inferred source, upstream rights changes or hosted CI claims.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
