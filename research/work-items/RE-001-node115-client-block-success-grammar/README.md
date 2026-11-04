# RE-001: node #115 complete ClientBlocks successful-wire structure

- Component: ClientBlocks response decoding; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Thirty complete FDEs,15,839 bytes. Exclusive ELF VA ends and call bindings are in `records.json`. Extents include context and error paths; they are not a claim that all enclosing behavior is reconstructed. All component gates remain false.

## Finding

Earlier work closes the ClientBlocks response's outer routing and error enum, but leaves its successful nested value opaque. This packet follows the successful path through the entire structural wire graph. It distinguishes the block's optional commit proof from the timeout parent's independent optional QC, binds the five-scalar QC layout, and closes the attached hash/blob framing. It does not assign a transaction type to the opaque blob.

The following notation is a concatenation grammar. `U64` and `U32` mean the little-endian variable-length integer readers, `B` means one raw byte, and `Raw(n)` consumes exactly n bytes without a length prefix. `Vec(T)` is `U64(count)` followed by count instances of T. Options use a **raw byte**, not a u32 enum tag. Zero means absent and one means present. The outer response/result and BlockParent tags use U32.

```text
SuccessfulClientBlocks = U32(0) U32(0) Vec(Client)
Client                 = Block Vec(Attachment)
Block                  = Signature Header Option(CommitProof)
CommitProof            = Signature Header QC
Header                 = Raw(20) Vec(Raw(32)) Timestamp Parent
Timestamp              = ZigZagI64 U32(nanoseconds)
Parent                 = U32(0) QC
                       | U32(1) TC Option(QC)
QC                     = U64(f0) U64(f1) U64(f2) U64(f3) U64(f4)
                         Raw(32) Vec(QCVote)
TC                     = U64(t0) QC Vec(TCVote)
QCVote                 = Raw(20) Signature
TCVote                 = Raw(20) U64(v0) Signature
Signature              = U64(r0) U64(r1) U64(r2) U64(r3)
                         U64(s0) U64(s1) U64(s2) U64(s3) B(recovery)
Attachment             = Raw(32) U64(byte_count) Raw(byte_count)
```

The scalar names `f0..f4`, `t0`, and `v0` are positional labels, not recovered semantic field names. Do not substitute the older three-scalar QC signing preimage for this five-scalar node115 decoder. The signature is65 bytes in its packed value representation, but **its wire representation is eight U64 varints and one raw byte**. A zero-limb signature therefore consumes9 wire bytes; eight maximal limbs consume73. No restriction of the recovery byte to0/1 is added by these readers. Cryptographic acceptance is a later question.

The header starts with a raw20-byte address and a count-prefixed vector of raw32-byte hashes. Its timestamp uses the previously studied signed-scalar and timestamp-admission readers. A QC parent has no following optional QC; a TC parent always has that option byte, even when absent. A commit proof has its own complete signature and header before its final QC. Its nested header may independently choose a TC parent and optional QC. The block's proof option is read before the attached-vector count.

The Client representation has no extra serialized tag for the `Unverified` or Arc wrappers. `0x5ab7f10` delegates to `0x4fbad90`, which reads the structured block through `0x4fb7760` and then the attachment vector through `0x5824840` with callback `0x4e04e90`. Arc allocations occur around the already decoded values. Attachment hashes are read before blob lengths. The specialized blob reader `0x5824b60` copies contiguous raw bytes; its supplied byte callback is not called on that optimized path. The bytes may contain arbitrary values, including variable-integer marker bytes, without inner decoding.

| Native boundary | Closed structural role |
| --- | --- |
| `0x59d5ea0` | address, hash vector, timestamp, parent; TC followed by optional QC |
| `0x4fb7760` | signature, header, raw-byte optional CommitProof |
| `0x4fbb010` | proof signature, independent header, QC |
| `0x5968d20` | five U64 scalars, raw32 hash, QC-vote map input |
| `0x5968f10` | leading U64, QC, TC-vote map input |
| `0x5820e50 / 0x542efe0` | QC signer20 then signature |
| `0x5820c70 / 0x542c290` | TC signer20 then extra U64 and signature |
| `0x4e04e90 / 0x5824b60` | attachment hash32 then count-prefixed raw blob |

After wire vote rows are decoded, existing map builders sort/deduplicate them. The relation fixtures use unique ascending signers with at most20 rows; their logical wire lists survive that normalization. Duplicate winner rules, the long sort and flat/tree representation are credited separate research, not newly claimed here.

## Validation and limits

The relations extract the actual header-address width, hash width, five QC scalar calls, signature limb call count, nested call targets and three discriminants from target instructions. An independently written canonical fixture encoder checks96 combinations of parent/proof choices, hash/attachment counts and vote counts,24 multi-client fixtures and the empty vector. Wide scalar boundaries distinguish varints from fixed-width assumptions. A hand-counted all-zero one-client success occupies76 bytes including the outer two tags and vector count. All proper prefixes of representative complete fixtures fail the structural reader. Four changed native operands change the TC parent tag, each independent Some tag, and the QC parent zero-discriminant branch.

These checks combine target-bound static evidence and mathematical structure relations; they do not execute or emulate the captured target and are not a native differential test. The fixture encoder is an independent test aid, not a reconstructed native writer. Its canonical output is a subset of accepted integer encodings. The structure reader's exact-end assertion belongs to fixture validation: the native response decoder need not consume an external buffer's trailing bytes.

The success contract assumes budget-disabled decoding and successful allocation. Primitive scalar validity, timestamp calendar/leap-second admission, voter-map normalization, complete malformed-input error payloads/cursor effects, budget accounting, allocation/destruction, cryptographic verification and transport framing remain explicit boundaries. Fixture timestamps are ordinary admitted values near the Unix epoch. No global acceptance or source-to-node equivalence is claimed. The complete blob FDE also shows its length charge and whole-payload availability check, but the relation does not pretend to reconstruct every decoder budget across the graph.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-client-block-success-grammar/export_disassembly.py
python3 research/work-items/RE-001-node115-client-block-success-grammar/verify.py --controls
python3 research/work-items/RE-001-node115-client-block-success-grammar/relations.py
python3 -m unittest discover -s tests -p 'test_node115_client_block_success_grammar.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-client-block-success-grammar/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

[PR #2790](https://github.com/lalalune/hyperliquid-source/pull/2790) closes ClientBlocks errors and identifies the successful ClientBlock payload as an unresolved next question. [#2784](https://github.com/lalalune/hyperliquid-source/pull/2784) and [#2795](https://github.com/lalalune/hyperliquid-source/pull/2795) cover sibling response values; [#2852](https://github.com/lalalune/hyperliquid-source/pull/2852) covers request consumption. [#999](https://github.com/lalalune/hyperliquid-source/pull/999) and [#1567](https://github.com/lalalune/hyperliquid-source/pull/1567) cover validation/buffering, not this complete decode graph.

[#1444](https://github.com/lalalune/hyperliquid-source/pull/1444), [#1467](https://github.com/lalalune/hyperliquid-source/pull/1467) and [#1391](https://github.com/lalalune/hyperliquid-source/pull/1391) supply older signing-preimage context. Their signed bytes are not assumed equal to node115 response bytes. Primitive predecessors [#2300](https://github.com/lalalune/hyperliquid-source/pull/2300), [#2412](https://github.com/lalalune/hyperliquid-source/pull/2412), [#2902](https://github.com/lalalune/hyperliquid-source/pull/2902) and [#2611](https://github.com/lalalune/hyperliquid-source/pull/2611) are credited rather than re-claimed. The separately prepared `RE-001-node115-client-block-timestamp-admission` and `RE-001-node115-certificate-voter-normalization` packets close timestamp admission and map normalization; this packet is self-contained and imports no unmerged code from them.

GPT-6.1 Terra searched all-state PR metadata and available file evidence. Inaccessible historical content and missing patches limit an absolute uniqueness guarantee. New analysis and relations are independently authored under MIT; evidence/export scaffolding reuses existing MIT packets. No unlicensed inferred source, full source equivalence, imported-rights changes or hosted CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
