# RE-021: type-2 transaction input for the address-09 precompile

The selected node #94 bytes support reconstructing the type-2 recipient and input decoding, their error branches, and their placement in a transaction environment, conditional on the decoded transaction reaching that converter.

- Component ID: `evm`; bounded extension of RE-021.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; separately pinned inferred reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference labels are not source authority; this packet is based on node bytes.
- Claim status: observation and bounded static inference; runtime reachability, execution outcome and complete component equivalence remain unresolved.
- Scope included and excluded: selected type-2 envelope, recipient, payload and signature parsing, success-path copies, environment conversion and payload ownership adapters. This is not the complete transaction pipeline or the registry lookup. The earlier [RE-021 packet](../RE-021-blake2b-compress-94/README.md) owns the compressor and address-09 wrapper; the distinct, pending registry/dispatch work is not repeated here. Node #115 and visor are excluded.

## Reproduce

From the repository root, with Python 3.12.3 and the authenticated node #94 artifact present:

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_blake2b_typedtx94
python3 tools/blake2b_typedtx94.py --out <tmp-dir>/first
PYTHONHASHSEED=17 TZ=Pacific/Honolulu python3 tools/blake2b_typedtx94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
python3 tools/catalogue.py --check
```

Replace `<tmp-dir>` with a writable scratch directory. The generator first verifies the full artifact SHA-256, then reads the ELF with the shared `tools/elf_index.py` and `tools/fde_extents.py` parsers. It requires only the Python standard library, invokes no external program, skips `SHT_NOBITS` in file-backed VA mapping and does not run the node or captured instructions. Its only writes are the generated evidence files in the specified output directory. `MANIFEST.sha256` covers this README and each generated evidence file. The synthetic transaction and projections are modeled examples, not executions or claims of signature validity.

## Evidence

All addresses below are linked virtual addresses before load bias; file offsets and original bytes are in the generated tables. The selected starts agree between `.eh_frame_hdr` and parsed `.eh_frame` FDEs. FDE ranges are unwind extents, not proof of all function boundaries or a complete call graph. Each selected range is file-backed executable text; `bodies.json` retains its raw bytes and `unwind.json` the raw FDE/CIE records. A restricted, fail-closed x86 length decoder walks these selected extents from their FDE starts. It adapts the repository MIT decoder in `tools/evm_kvs_inventory.py` for two additional observed SSE forms; unknown encodings fail rather than resynchronize. `instructions.tsv` retains every decoded byte and boundary, `control-flow.tsv` records every recognized transfer shape, and `flow-summary.tsv` totals them per extent. Direct local transfers and selected switch entries must land on decoded starts. A linear decode is not a reachability proof or a complete dynamic call graph; external transfer destinations are intentionally omitted from that census.

| Selected start(s) | Bounded role inferred from the byte relationships |
| --- | --- |
| `0x46c2d30` | Raw envelope entry, digest/recovery gate, and success/error publication |
| `0x4e4e600`, `0x4e52fb0`, `0x134d5c0` | Typed switch, type-2 list, and sequential unsigned-field decoding |
| `0x135b670`, `0x134e410` | Recipient option and byte-string payload decoders |
| `0x4e55db0`, `0x4e56860` | Parity and two scalar decodes |
| `0x4e50020`, `0x4e58840` | Digest and recovery adapters; their external implementations remain opaque |
| `0x4e4eee0` | Tagged transaction to environment conversion |
| `0x1510c10`, `0x1510c60`, `0x1510520`, `0x1510360` | Two initial clone adapters, promotion and shared clone |

### Recipient and input movement

The byte at the raw entry is read only if the supplied length is nonzero. An input byte with its high bit clear is consumed as a type and dispatched by `0x4e4e600`. Its table at `0x7c1660` sends index 2 to `0x4e4e76e`, which calls `0x4e52fb0`. Type values above 4 go to the recorded error arm. The selected type-2 field decoder calls five preceding field helpers, then the recipient decoder through relocation slot `0x576e208`; it subsequently calls the value, byte-string and access-list helpers in that order. Field names are inferred from position and data shapes, not debug symbols.

The prior RE-021 object address bytes at VA `0x574f0c0` (file offset `0x574d0c0`) are 19 zero bytes followed by `09`. The following table projects only the 21 defined lanes on the address-present success arm, assuming normal helper returns, no helper mutation of the saved recipient, and nonaliasing. Offsets are relative to each indicated result or input object, not ELF addresses. The selected moves include overlapping 16-byte and 8-byte stores; `lanes.tsv` projects every lane, including the overlap.

| Stage | Tagged recipient location | Observation |
| --- | --- | --- |
| `0x135b670` result | `+0x01..+0x15` | Inner tag 1, then the 20 input address bytes; outer status at `+0x00` is success |
| `0x134d5c0` result and `0x4e52fb0` result | `+0x90..+0xa4` | Preserved through staged and bulk copies |
| `0x4e4e600` output; `0x46c2d30` published success object | `+0xa0..+0xb4` | The selected typed arm adds the tag region; the raw-entry success copies preserve the field under those assumptions |
| `0x4e4eee0` input to environment output | input `+0xa0..+0xb4`; output `+0x13c..+0x150` | Selected index-2 arm copies the tag and address |

The raw entry's selected digest and signature recovery must succeed and its final sentinel comparison must take the non-equal arm before the selected success publication; their external callees are not proved to preserve the saved object. The comparison and call data shapes do not establish which caller supplies its result to the separately invoked converter. If the converter writes the transaction-environment subobject used in pending PR #1563, that packet reports the same tagged recipient is copied to the frame lookup key. Pending PR #1413 maps one provider route, and pending PR #1373 maps the standard registry entry to the existing wrapper. These are credited dependencies, not bodies selected or revalidated here: their normal-return, provider-selection, no-override and lookup guards must all hold. The environment output is therefore a conditional composition of byte-backed slices, not proof that a real submitted transaction reaches a particular precompile registry or invokes compression.

On the selected nonempty byte-string path, `0x134e410` advances the RLP cursor, calls the allocator-like target through slot `0x576dfd8`, and calls the dynamic `memcpy` symbol through `0x576dfe0`. The result carries a table pointer, copied-data pointer, length and owner word. In the unsigned-field result these four words are at `+0x20`, `+0x28`, `+0x30`, `+0x38`; in the type-2 converter input they are at `+0x30`, `+0x38`, `+0x40`, `+0x48`. The converter calls the first table entry and places the returned four-word clone at environment `+0xc0`. `payload-layout.json` records the decoded instruction operands and resulting four-word offsets. The pinned adapters carry the same data pointer and length through that clone. These are compatible layouts: the unproved caller handoff and intervening helper effects could change the words before conversion. Behavior of other table implementations and memory aliasing is outside this claim.

The earlier wrapper evidence requires 213 input bytes. `synthetic-transaction.json` independently constructs a type-2 serialization with the artifact-derived address and an all-zero 213-byte example input. Its byte-string field begins `b8 d5`; its zero signature scalars are deliberately unchecked. This fixture is **not** a captured transaction, a cryptographic test vector, evidence that the wrapper accepts the other fields, or a target execution. The separate recipient, payload and signature case files are synthetic projections of the pinned arms.

### Failures, ownership and state changes

The following examples describe the static projections, with raw codes rather than invented error names. `consumed` means cursor bytes advanced at the selected decoder; it is not a statement about the caller's final error representation.

| Selected branch or example | Bounded result |
| --- | --- |
| Recipient `80` | Success with absent option, consumed 1; the unused address payload is not claimed initialized |
| Recipient `94` plus exactly 20 bytes | Success with present option and 20-byte value, consumed 21 |
| Recipient `94` plus only 19 bytes | Error 2, consumed 1; the 20-byte success copy is not taken |
| Recipient `93` plus 19 bytes | Error 5, consumed 20; full input is present but width differs |
| Recipient `81 00` / `b8 14` / `b8 00` | Errors 3 / 4 / 1, respectively, after the recorded prefix/length consumption |
| Payload `b8 d5` plus 213 bytes / plus 212 bytes | Predicted byte result of length 213 / error 2 after the two-byte header |
| Parity `80` / `01` / `00` / `02` | Values 0 / 1 / error 1 / error 9 |
| Scalar `80` / literal `00` / nonzero 33-byte value | Value 0 / error 1 / error 8; a parsed zero is not a claim of valid signature recovery |
| Type-2 outer list | Checked addition has a carry branch; a consumed-length mismatch takes the recorded tag-8 path |
| Raw signature gate | The extracted four-limb unsigned bound is in `signature-bound.json`; strictly greater takes `0x46c30e3`, equality alone does not. A zero recovery-result byte also takes that error arm |
| Raw output sentinel | The selected equality branch at `0x46c30bc` goes to alternate publication; the described success copy takes its fallthrough |

A copied nonempty payload selects initial table `0x5670ae8` or `0x5670ac0` from the low bit of the allocation pointer. Their relocated first entries are the selected clone adapters. For a marked owner, they reach `0x1510520`: it checks carry on the computed size, requests 24 bytes, stores the base, computed size and initial count 2, then performs a locked compare-and-exchange on the owner word. Its success arm installs the new shared owner; on a lost comparison the selected arm increments the observed owner's count, returns that owner with the same data pointer and length, and takes the recorded cleanup transfer. Size overflow, allocation failure and signed refcount-failure branches are in `branches.tsv`. This description assumes the surrounding owner invariants and says nothing about scheduler fairness or arbitrary allocator behavior.

In the converter's selected type-2 arm, the recipient is stored before the input clone is installed. The `.gcc_except_table` record for the old-input callback at `0x4e4f237` names landing `0x4e4f7e6`; the pinned landing bytes store the new clone in the destination and then make a direct external call. The external call semantics are not reconstructed. Other exception actions/types and external callbacks are not reconstructed. `exception-sites.tsv` retains every decoded call-site row for the selected LSDAs, including entries with no landing.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no new Cargo target or lockfile, native code build, captured-node execution, normalized comparison, helper closure, whole-ELF comparison or equivalence claim. The packet supplies static ABI/layout decisions and synthetic expected cases only. The saved body bytes are evidence, not transplanted implementation. No byte normalization masks were applied.

The independently decoded synthetic transaction in the tests checks the generated RLP field order and rejects a truncated enclosing list. The tests also check all 160 individual address-bit changes through the bounded copy projection, short-field widths and truncations, 213-byte payload boundaries, parity/scalar cases, and the four-limb comparator against independently assembled integers. Negative controls corrupt authenticated bytes, selected unwind-index entries and FDE pointers, each selected instruction window and a payload displacement, relocation addends and duplicate slots, a switch entry, a branch opcode/target, an LSDA header, an unsupported or truncated instruction, a branch into an instruction, and out-of-range or NOBITS mappings. They do not emulate target instructions.

## Results and limitations

The generator records **15 selected FDE ranges / 11,628 raw bytes / 2,478 decoded instructions**, **392 decoded transfer records** including **156 conditional branches**, **58 selected windows**, **27 selected direct or slot calls**, **48 separately annotated conditional branches**, **15 switch entries**, **13 relocations**, **7 RIP-relative references**, and **53 call-site rows in 6 selected exception tables**, of which 25 have a landing. These are selected-slice counts, not coverage denominators for the node. It also emits 21 projected recipient lanes, 14 recipient cases, 15 payload cases and 13 signature cases. The focused Python suite has 23 tests and no skips. See `summary.json` and `MANIFEST.sha256` for machine-readable counts and file hashes.

No full-scope progress gate is requested. The outstanding question is whether a non-overlapping, target-backed caller chain can show that this raw decoded object is delivered unchanged to this converter and then to the specific runtime lookup already under separate review; actual registry selection, precompile invocation, gas and execution behavior remain unproved here.
