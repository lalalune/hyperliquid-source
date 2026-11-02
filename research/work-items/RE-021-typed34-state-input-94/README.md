# RE-021: typed transaction inputs for the address-09 path

Node #94's type-3 and type-4 decode paths preserve a 20-byte recipient into the layout expected by the existing transaction-environment converter, and the type-4 path separately constructs the authorization rows that converter copies; this makes their parser layouts and selected rejection/cleanup branches reconstructible while keeping execution reachability conditional.

- Component ID: `evm`, bounded continuation of RE-021.
- Target release and full SHA-256: node #94, Linux x86-64, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not source authority, and no reference code is copied.
- Claim status: **observation** for the retained bytes, file/VA mappings, unwind records, relocation forms and decoded instruction shapes; **inference** for field names, described branch effects and composition across separately owned calls; **unresolved** for actual execution, signature validity, state success and lookup reachability.
- Scope included and excluded: 21 newly selected FDE ranges for signed type-3/type-4 envelopes, their selected field parsers, allocation/list behavior and cleanup. The dispatcher, tagged-to-environment converter, preparation/state functions, providers, lookup, address-09 object and compression wrapper are previously studied dependencies, not new selected FDEs. Their small interface anchors are included only to check composition. Node #115, visor, captured execution/emulation, networking and full EVM reconstruction are excluded.

## Reproduce

Run from the repository root with the authenticated node #94 artifact. The extractor first checks the complete SHA-256, then uses only Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. It excludes SHT_NOBITS from file-backed mappings, invokes no other programs and never executes or emulates captured code. Its sole writes are the generated files in the supplied output directory. Python 3.12.3 on Linux x86-64 was used. GNU objdump 2.42 was used for human inspection only; neither the generator nor the tests call it or consume its output.

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_re21_typed34_inputs94
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/re21_typed34_inputs94.py --out <tmp-dir-a>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/re21_typed34_inputs94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
python3 tools/re21_typed34_inputs94.py --out research/work-items/RE-021-typed34-state-input-94
```

Replace the two placeholders with different empty writable directories. All JSON and TSV files in this directory are generated. The README and manifest are packaging files; `MANIFEST.sha256` covers each other file in this directory. The relative commands work without a binutils installation. Hashes and full original bytes for selected ranges and unwind records are retained in the generated files.

## Evidence

### Boundaries, function map and dependencies

All addresses in this section are linked ELF virtual addresses before load bias; file offsets and raw bytes are in the tables. `.eh_frame_hdr` entries agree with the corresponding shared-parser FDE records for all selected ranges. Each range is executable and file-backed. `functions.tsv` records starts, exclusive ends, original file offsets, FDE/CIE/LSDA coordinates, indices and body hashes; `bodies.json` and `unwind.json` retain raw bytes. An unwind extent is not by itself proof of a source function boundary. A restricted, fail-closed x86 length decoder walks the selected extents linearly, with local branch targets checked against decoded starts. `instructions.tsv` and `transfers.tsv` preserve that walk; it is not a reachable CFG or a whole-node function census. The decoder is adapted from the MIT-licensed `tools/evm_kvs_inventory.py` and does not use binutils.

| Selected FDE start(s) | Inferred bounded role |
| --- | --- |
| `0x4e51a50`, `0x4e559d0` | Signed type-3 and type-4 envelope decoding, length check and error publication |
| `0x1346db0`, `0x1349530` | Unsigned type-3 and type-4 field order, inline recipient and output stores |
| `0x1348390`, `0x134aa40` | Integer payloads bounded by 8 bytes |
| `0x13485a0`, `0x134ac50` | Integer payloads bounded by 16 bytes |
| `0x13487c0`, `0x134ae70`, `0x1354d30` | Integer payloads bounded by 32 bytes, including the type-4 row helper |
| `0x1348a80`, `0x134b130`, `0x1348310`, `0x134a9c0` | Address/key access-list rows and selected vector cleanups |
| `0x1349140` | Type-3 vector of 32-byte elements, also used for access-list keys |
| `0x134a770` | Type-4 byte-string input and its allocation/copy boundary |
| `0x134bbd0`, `0x1355110` | Type-4 authorization vector and decoded authorization row |
| `0x4e51e50`, `0x4e56190` | Type-3/type-4 temporary cleanup after signed decoding |

`dispatch-boundaries.json` checks two previously owned dispatcher table entries and their calls to the newly selected signed decoders. Relocations in `relocations.tsv` bind their unsigned-parser slots `0x576e120` and `0x576e168` to `0x1346db0` and `0x1349530`, and bind the row-decoder slot `0x576e188` to `0x1355110`. `field-calls.tsv` records 19 ordered direct calls; inline recipient parsing falls between the gas and value calls. Type 3 subsequently parses a fee and a 32-byte-element vector; type 4 instead parses an authorization vector. The type-3 byte-string producer `0x13480c0` is an external boundary, not a selected body.

The prior [compression packet](../RE-021-blake2b-compress-94/README.md) identifies the address-09 object and wrapper. The earlier typed-transaction packet (PR #1733) owns the shared dispatcher and converter; the preparation packet (PR #1563) owns the environment-to-frame copy and authorization state processing; the runtime and provider packets (PRs #1373 and #1413) own the registry and dispatch route. `prior-interface-windows.tsv` retains only short byte anchors for the interfaces used here; none of those earlier FDEs is selected, and this packet does not claim their coverage as new work. The prior public PR inventory was supplied as a snapshot, so ownership should be refreshed at submission.

### Recipient and input movement

The selected unsigned decoders both check a recipient width of 20 on the short-byte-string branch and save the loaded bytes across later field calls. Their output stores overlap deliberately; `recipient-lanes.tsv` lists the writer count for every input lane. Assuming successful later calls, ordinary copies and no destructive alias, the signed wrappers copy those same 20 lanes into their results. `handoff-lanes.tsv` composes these newly selected stores with the previously owned dispatcher and converter anchors:

| Type | Unsigned and signed result address | Previously mapped tagged result address | Prior converter output |
| --- | --- | --- | --- |
| 3 | `+0xb8..+0xcb` | `+0xc8..+0xdb` | tag byte 1 at `+0x13c`, address `+0x13d..+0x150` |
| 4 | `+0xa8..+0xbb` | `+0xb8..+0xcb` | tag byte 1 at `+0x13c`, address `+0x13d..+0x150` |

Offsets are relative to the indicated object, not ELF addresses. The artifact's prior address key at `0x574f0c0` is nineteen zero bytes followed by `09`; `synthetic-cases.json` retains the file-backed bytes and projected short-string cases. If this unchanged decoded result is supplied to that prior converter, and its output is the environment subobject used by the earlier preparation path, that earlier work copies the resulting address to the frame lookup key. The required caller handoff has **not** been established here. Later callback selection, provider registration, account/value/depth checks and normal helper returns are also conditions; the composition does not prove that any submitted transaction invokes the address-09 wrapper.

For type 4, the selected `0x134a770` body reads the length and checks that the full byte-string payload remains before its allocator/copy boundary. A nonempty result selects one of the previously mapped clone tables. `payload-words.tsv` records the method table, data pointer, byte length and owner at unsigned offsets `+0x20`, `+0x28`, `+0x30`, `+0x38`, then the prior tagged offsets and the converter's `+0xc0` clone-result destination. The type-3 caller stages the same four returned words, but the earlier-owned type-3 producer is not independently characterized here. The original bytes are preserved only under the earlier clone-adapter contract, ordinary helper returns and compatible ownership; a copy into a particular live frame is not proved.

The earlier wrapper reports a 213-byte input requirement. For the selected type-4 long-string arm, the synthetic `b8 d5` header followed by 213 bytes yields a projected 213-byte payload; 212 following bytes take the short-input branch. The `b8 d5` example, bit projections and constructed transactions are not captured transactions or proof that signatures, gas or precompile-specific input fields are valid.

### Vector, integer and failure branches

`0x1349140` checks each selected list element's 32-byte width and copies its byte lanes into a 32-byte-stride vector. `key32-lanes.tsv` records all lanes. The selected parser returns an empty vector for an empty list and releases vector storage on a later element error; no source-level validity rule for a hash's first byte is implied. In the type-4 vector, the row decoder returns an address distinct from the transaction recipient, at offset `+0x28` within the 136-byte row; `authorization-lanes.tsv` records its 20 projected lanes. The vector copies a row before incrementing its initialized count and frees allocated capacity on the selected error arm. An empty authorization vector is syntactically produced by this parser; the earlier preparation packet reports separate downstream rejection/eligibility checks. Neither result implies a valid authorization.

For a normal type-4 converter copy, the pinned prior interface anchors independently show the authorization pointer/count move from unsigned result `+0x98/+0xa0` to tagged result `+0xa8/+0xb0`, and a copy of 136 bytes per row into a converter output with tag 0 and capacity/pointer/count at `+0x78/+0x80/+0x88`. `layout.json` records these displacements and the copy size. That prior preparation packet describes later conditional account code/hash/nonce/flag updates for eligible rows; the parser, vector copy, signature/recovery, account eligibility and normal-return assumptions all remain necessary to connect those writes to this input. They are not newly analyzed state functions in this packet.

`decisions.tsv` records 62 annotated selected conditional branches, each with original bytes, taken target and fallthrough. `transfers.tsv` retains the broader linear set. The following table summarizes only the indicated arms; error words are raw values rather than invented source names and consumed counts describe the selected input cursor.

| Condition or synthetic input | Bounded static projection |
| --- | --- |
| Empty recipient input | Error word 2, consumed 0 |
| `80`, or `93` followed by 19 bytes | Error word 5, consumed 1 or 20 respectively |
| `94` followed by 19 bytes | Error word 2, consumed 1 |
| `94` followed by 20 bytes | Address bytes copied, consumed 21 |
| `b8 d5` followed by 212 / 213 bytes, type-4 input | Error word 2 after the header / 213-byte payload after 215 total bytes |
| Empty / 31-byte / truncated 32-byte-element list example | Empty vector / error word 5 / error word 2 |
| Integer payload wider than 8 bytes, 8-byte helper | On the selected arm, result word at `+0` is 0 before any leading-zero test |
| Integer payload wider than 16 bytes, 16-byte helper | On the selected arm, result tag at `+0` is 1 and detail at `+8` is 0, before a leading-zero test |
| Integer payload wider than 32 bytes, 32-byte helpers | On the selected arm, result tag at `+0` is 1; detail at `+8` is 1 for a leading zero and 0 for a nonzero first byte |
| Signed envelope declared length does not match consumed length | Word 8 followed by the corresponding temporary cleanup |

The signed wrappers also contain carry/borrow failure transfers, unsigned-decoder sentinel and signature-result branches; their external handlers and signature semantics are not reconstructed. Type-3 and type-4 cleanup ranges iterate access rows and release nonzero nested capacities; their extra vector allocations use 32-byte and 136-byte strides respectively. Dynamic payload destruction is an external boundary. `exception-headers.json` and `exception-sites.tsv` retain selected LSDA headers and call-site entries, including the signed-wrapper landing pads that call cleanup and transfer to unwind. Action chains, catch types and all external helper effects remain unresolved.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lockfile, compiler/linker flags, native two-build comparison, masks, relocation/helper closure, whole-ELF comparison, captured-node execution and behavioral equivalence: **not yet implemented/measured**. No normalization masks or byte-transplanted Rust implementation are claimed.

The Python synthetic functions express only selected instruction-derived projections; they do not execute, interpret or emulate captured instructions. The tests independently encode/decode constructed envelopes, check recipient/list/payload width and truncation boundaries, compare integer projections with Python integers, and exercise all 160 recipient-bit, 256 key-bit and 160 authorization-address-bit positions. They also corrupt the target digest, every selected/prior interface pin, unwind pointers and duplicate FDEs, relocation types/addends/duplicates, a recipient predicate/target, an exception header, and out-of-range, crossing, ambiguous and NOBITS address mappings. They reject unsupported/truncated instruction shapes and a local branch into an instruction. These checks validate the extractor and bounded projections, not real transaction acceptance.

## Results and limitations

The generator records **21 selected FDE ranges, 19,011 bytes and 4,698 linearly decoded instructions**; **894 transfer records**, including **498 conditional transfers**; **131 selected byte windows**, **44 prior interface anchors**, **62 annotated decisions**, **19 ordered field calls**, **31 relocation entries**, and **46 call-site intervals in 8 selected exception tables**, 21 with landing pads. It emits 40 recipient-lane rows, 40 conditional handoff-lane rows, 32 key-lane rows, 20 authorization-address-lane rows and 8 payload-word rows. See `summary.json` and `MANIFEST.sha256`. These counts describe a deliberately selected corpus, not function coverage or an EVM completion denominator.

The focused suite passed **25 tests, zero skips**; two independent generations and the repository artifact/catalogue checks are recorded in the draft. No full-scope progress gate is requested: the `evm` milestone remains 0/4. This packet does not establish the raw-entry-to-converter caller, selected type-3 input producer internals, external signature/recovery/allocator behavior, complete source types, complete EVM state transition, runtime registry selection, actual compression or target equivalence.

Next question: find a still-unowned caller chain, if one exists, that passes the decoded type-3/type-4 result unchanged to the identified converter and establishes which prepared environment and provider reach the frame lookup; retain all independent ownership and runtime assumptions.
