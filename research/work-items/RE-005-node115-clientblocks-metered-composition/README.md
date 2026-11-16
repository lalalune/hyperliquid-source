# ClientBlocks success: cumulative reader budget and actual parent composition

Target: node/115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes. Static ELF/FDE and instruction inspection only; the captured executable was neither run nor emulated.

## Remaining scope and prior work

This addresses the request/response caller-integration gap in #3907. It reuses the existing successful structural grammar (`RE-001-node115-client-block-success-grammar`, #2916), scalar reader implementations, and composed response discriminant/error handling. It does not present that grammar as newly discovered. The prior `RE-001-node115-clientblocks-decode-ownership` packet covers native allocation ownership; #7047 separately reconstructs the attachment reader's cumulative state. Neither supplies the complete success decoder with one budget shared across its real parent and all nested children.

The new API reconstructs that state propagation, including reservations that can fail before the eventual fields would exhaust a budget. `decode_payload_prefix_metered` returns both the remaining input and charged count on success or failure. The existing unmetered API is retained. The opt-in composed-parent API uses the state left by its existing two discriminants; existing public enums and the old boundary-returning API are unchanged.

## Native path and reader contract

`0x5aac7c0` selects the Result-success branch, binds callback `0x5ab7f10` at `0x5aac96c`, and calls vector reader `0x5824f20` at `0x5aac979` with the same reader. The callback reaches `0x4fbad90`, which decodes a block through `0x4fb7760` followed by the attachment vector. Block and proof signatures use `0x5821020`; headers use `0x59d5ea0`. The proof child `0x4fbb010` reads signature, header, then QC.

For canonical reader modes 0 (unlimited) and 1 (limited), cursor is at reader +0x10/+0x18 and charged count is at +0x20. Limited operations checked-add their typed charge before input availability. A representable sum is stored before the limit comparison, so an over-limit error retains the new sum. Arithmetic overflow returns before the store. Unlimited mode leaves the supplied counter unchanged. These are typed allocation/field charges, not consumed wire-byte counts.

Each vector first reads a U64 count (charge 8), checked-multiplies count by its row reservation, then checked-adds/stores that reservation. Before each child it refunds one row. A failed child retains the reservations of all unvisited rows. Neither counter nor cursor is rolled back.

| Vector | Native entry | Callback | Reservation per row |
| --- | --- | --- | ---: |
| Clients | `0x5824f20` | `0x5ab7f10` → `0x4fbad90` | 16 |
| Header hashes | `0x5824340` | `0x4e182e0` → fixed32 | 32 |
| QC votes | `0x5825e60` | `0x5820e50` | 96 |
| TC votes | `0x58258f0` | `0x5820c70` | 104 |
| Attachments | `0x5824840` | `0x4e04e90` | 40 |

The QC binding is `0x4de647d`/`0x4de6489`; the TC binding is `0x5969029`/`0x5969038`. These widths refer to native row storage, not serialized length. QC rows charge 20 for the signer and 65 for the signature; TC rows add one U64 (8). Thus final charges of 85 and 93 are smaller than their transient reservations of 96 and 104.

Signatures are **two four-U64 arrays**, followed by a charged raw recovery byte. `0x5821540` reserves 32 before reading any of its four words, refunds 8 before each word, and invokes the ordinary charged U64 reader. A truncated first word therefore retains the other three words' reservations. Replacing this with eight independent scalar reads gives incorrect early-limit behavior. The QC helper `0x542efe0` and TC helper `0x542c290` bind the same arrays; the latter first reads its extra U64.

Timestamp entry `0x4ece880` charges 8 before the unmetered little-endian signed reader `0x5659e00`, then invokes charged U32 reader `0x5821150` for nanos (4), before timestamp admission. U32 parent tags charge 4. Fixed20 and fixed32 fields charge their full widths before availability and consume only when all bytes exist. Optional QC/proof tags charge 1, then consume a present byte before deciding whether 0/1 is valid. Recovery bytes are not restricted to those option values. Attachments charge fixed32, U64 length, then the decoded blob length before checking blob availability.

The existing scalar readers retain their native fast/slow marker and short-input behavior. This change reuses those readers rather than flattening cursor effects into a generic varint parser.

## Independent boundary examples

A minimal one-client QC-parent wire with zero-valued small integers, no hashes/votes/proof/attachments is 74 bytes but charges **206**:

`8 + 65 + 20 + 8 + 8 + 4 + 4 + (5*8 + 32 + 8) + 1 + 8`.

With limit 39, the outer count consumes one byte and charges 8; the client reservation raises this to 24 then is refunded to 8; the first signature array stores 40 and fails before reading any limb. A counter based on wire bytes or independent scalar reads misses this result.

For the same minimal prefix with one QC vote, the charge before vote reservation is 197. The 96-byte reservation stores **293** and fails at limit 292, even though a complete decoded row would yield final charge 291. With two QC votes, reservation reaches 389; refunding the first 96 and charging its missing 20-byte signer leaves **313**, while the second row remains reserved.

The minimal TC-parent equivalent charges 213 before its vote reservation. One 104-byte reservation reaches **317**, so limit 316 fails although a complete one-vote payload would finish at 316. A U64_MAX client count fails multiplication before allocation while retaining the count's charge and consumed cursor. The existing nested TC/optional-QC/proof/QC-vote/attachment fixture independently sums to 858, or **869** with initial charge 11. Parent composition with two U32 tags and an empty success vector charges **16** and preserves trailing bytes.

These expectations are asserted in the source tests. They are static reconstruction fixtures, not captured runtime observations.

## Reproduction

With Capstone 5.0.7 and pyelftools 0.32 installed:

```sh
python3 research/work-items/RE-005-node115-clientblocks-metered-composition/verify.py --target artifacts/node/115/hl-node
cargo test --manifest-path src/node115-client-block-success/Cargo.toml
cargo test --manifest-path src/node115-gossip-response-composed/Cargo.toml
```

The verifier checks the target digest, 29 FDE-bounded byte transcripts (3627 instructions), 103 selected instruction witnesses, and 10 negative controls. Controls reject a changed target, incorrect row widths, absent refunds, incorrect signature reservation, a double-charged timestamp dispatch, and the wrong TC callback. Transcript checks establish reproducibility of the cited static evidence; they are not dynamic execution or a general semantic equivalence proof.

## Limits

The output remains the prior decoder's structural representation, including vote rows and duplicates. Native certificate sorting/map normalization, container layout, error-union bytes, allocation failures/aborts, unwind behavior, and ABI equivalence are excluded. Successful allocation and ordinary returns from the reused scalar/timestamp helpers are assumptions of the source-level reader comparison. Timestamp validation reuses the prior source contract; this work does not redefine it. No signature/quorum validation, live peer framing, checkpoint admission, trusted expected root, or full component completion is claimed. The downstream consumer is the source-built GossipRpcResponse success path, not a live node.
