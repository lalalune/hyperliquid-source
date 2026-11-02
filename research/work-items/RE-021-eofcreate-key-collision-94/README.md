# RE-021: derived creation address and precompile collision in node 94

Subject to the executor and callback binding assumptions below, the selected creation path derives a 20-byte address from an 85-byte salted-hash input, carries it into a registry membership check, and increments the caller's nonce before a matching address 09 returns status `0x5e`; a reconstruction can preserve that ordering and the separate checkpoint rollback on a later failure.

- Component ID: `evm`; RE-021 extends the existing BLAKE2b precompile question and is not a separate row in the task table.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository baseline `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied.
- Claim status: **observed** for authenticated ELF bytes, selected instruction shapes, branch destinations, relocation and unwind records; **inferred** for source-level names, address-hash interpretation, and composition across the separately owned callback and registry boundaries; **unresolved** for live reachability, complete helpers, all fork differences and behavior equivalence.
- Scope included and excluded: eleven new FDE intervals covering one interpreter loop, opcode `0xec`, its two hash wrappers, two revision-specific creation adapters, the caller nonce, checkpoint setup and the selected reverse-journal path. The older executor, registry constructor, membership helper, BLAKE2b wrapper and compressor are dependencies; their bodies are not selected here. Node #115, visor, captured execution and the complete HyperEVM component are excluded.

## Reproduce

From the repository root, with the pinned artifacts available. The recorded analysis used CPython 3.12.3 on Linux x86-64 and GNU objdump 2.42 for human instruction review. The exporter uses only the Python standard library and the existing `tools/elf_index.py` and `tools/fde_extents.py` readers. It authenticates the full artifact before parsing, rejects NOBITS as file bytes, and does not invoke external programs or execute captured instructions. All JSON and TSV files in this folder are exporter outputs; this README and the manifest are packaging files.

```sh
python3 tools/evm_create_collision94.py --out research/work-items/RE-021-eofcreate-key-collision-94
python3 -m unittest tests.test_evm_create_collision94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-eofcreate-key-collision-94 && sha256sum -c MANIFEST.sha256)
```

For a determinism check, replace each placeholder with a distinct, empty relative directory:

```sh
PYTHON_BIN=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/evm_create_collision94.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/evm_create_collision94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$PYTHON_BIN" -m unittest tests.test_evm_create_collision94
```

## Evidence

All addresses are linked ELF virtual addresses before load bias, and FDE ends are exclusive. `functions.tsv` gives the corresponding file offsets, FDE/CIE/LSDA coordinates and SHA-256 of every selected body. `unwind.json` retains the actual unwind-header entry and CIE/FDE bytes; unwind extents alone are not claimed as a complete function map. `windows.tsv` contains reviewed bytes at selected instruction boundaries. `transfers.tsv` checks only the listed fixed transfer shapes and signed displacements; it is not a full disassembler or CFG. `immediates.tsv` directly decodes 28 selected instruction operands, including failure statuses, gas and depth thresholds, frame size, flags and journal tags. `exceptions.json` preserves bounded LSDA call-site records, not exception action chains. `relocations.tsv` records selected symbol-free relative relocation slots and their addends, and `linkage.json` retains the table words and data constants.

| New FDE start | Selected observation |
| --- | --- |
| `0x4c09420` | Plain interpreter loop fetches an opcode byte, advances its pointer, calls an eight-byte table slot and returns the installed action. |
| `0x4c98d40` | The selected `0xec` slot's handler checks flags, gas and stack, derives a key, and publishes a 336-byte action tagged `0x6e`. |
| `0x49d9990`, `0x4597bb0` | The first hashes a selected byte slice; the second hashes an explicitly assembled 85-byte buffer and copies digest bytes 12–31. |
| `0x4da6f00`, `0x4da5f30`, `0x4dd8d50` | The two callbacks supply bytes 9 and 18 to the same creation-frame routine, which takes the derived key through the earlier membership-helper boundary. |
| `0x4dd6b40`, `0x4dd6580` | The first updates a keyed account's 64-bit word and journal; the second opens a checkpoint and performs selected account checks and writes. |
| `0x4dd63d0`, `0x4675da0` | The first decrements checkpoint depth and invokes the second to traverse journal records in reverse; selected tags undo nonce, flags and balance changes. |

### Callback boundaries and provenance

The existing [BLAKE2b packet](../RE-021-blake2b-compress-94/README.md) pins the address-09 key and callback. Open PR #1373 maps the mode-2 and mode-5 registry lineages and generic precompile dispatch. Open PR #1676 owns the standard executor and its revision selection; its recorded raw-9/10 case calls constructor `0x4ddd3f0` and selects the mode-2 provider, while raw 18 calls `0x4ddce80` and selects mode 5. It also studies a **different** creation callback and membership FDE. This packet selects neither its executor nor that callback/helper.

The byte-derived relocations for slot `0xec` in tables `0x5723e88` and `0x5724688` both point to `0x4c98d40`. Descriptor method slots `0x5745e28` and `0x5745cd8` point respectively to new adapters `0x4da6f00` and `0x4da5f30`; the adapters pass immediate bytes 9 and 18 to `0x4dd8d50`. The selected opcode's action has tag `0x6e`. The four retained relative words at `0x6fd0ec` include index 2 targeting `0x47f3880`, inside the executor already owned by #1676. The link from the action to that executor's `+0x278/+0x280` callback pair, and installation of descriptors `0x5745e00` or `0x5745cb0`, are **composition dependencies on the existing executor/builder**, not newly selected function bodies. In particular, a relocation alone does not prove that a live engine uses either descriptor. The correspondence assumes the earlier selector and frame-copy relations, unmodified callback pairs and ordinary helper returns.

Three selected diagnostic Location records resolve to a binary-embedded path whose retained **relative suffix** is `revm-interpreter-15.0.0/src/instructions/contract.rs`, with line/column pairs `(49, 50)`, `(53, 9)` and `(27, 10)`. Ten further records reached from the selected nonce, checkpoint and rollback FDEs share suffix `revm-19.2.0/src/journaled_state.rs`; for example they include `(182, 52)`, `(270, 52)` and `(452, 9)`. The exporter verifies the RIP-relative instruction targets and relocated path pointers, and records their bytes, full-path digest and sanitized suffix in `linkage.json` and `relocations.tsv`; the original paths are not emitted. The adjacent interpreter diagnostic bytes identify EOF and a verified subcontainer. These are dependency/version clues for the selected instruction family, not proof of unmodified upstream code, a reth revision, or complete private-fork boundaries.

### From input to the address key

For the selected `0xec` handler, interpreter byte `+0x1f0` equal to zero writes status `0x67`; a nonzero byte at `+0x1f2` on the other arm writes `0x57`. Otherwise remaining gas must be at least `0x7d00`. The handler subtracts this base charge before checking that four 32-byte stack words are present; an insufficient stack writes `0x5b` after that subtraction. The selected high-word and memory-growth failures write `0x54` and `0x51`, and a later failed cost subtraction writes `0x50`. A decoder sentinel takes a diagnostic call followed by `ud2` if the call returns. The binary-derived windows and transfer rows retain the selected guards and destinations; external decoder, allocator and memory helper behavior is not modeled as observed execution.

On the selected normal arm, the opcode calls `0x49d9990` on a slice supplied by a dynamic subcontainer callback. That helper initializes a state with rate `0x88` and delimiter word `1`, calls the prior absorb/finalize slots, and returns 32 bytes. The opcode reverses the selected 32-byte stack word, passes its own 20 bytes at interpreter `+0x80`, the reversed word and that digest to `0x4597bb0`. The latter assembles and hashes exactly:

```text
ff || address[20] || salt_bytes[32] || payload_digest[32]
```

It copies the final 20 bytes of the 32-byte result. The rate, delimiter, digest length, input copy offsets, relocated calls, and digest-slice stores are pinned. The interpretation as Keccak-256 and a CREATE2-style address follows the combination of those observations and the earlier Keccak evidence; the dynamic payload's full provenance and semantics are not established by its pointer alone. Tests include an independent synthetic Keccak oracle and a fixed CREATE2 example, not target execution.

The handler stores the computed key in the constructed frame at `+0xf8..+0x10b` and a separate 20-byte value from interpreter `+0x80` at `+0x138..+0x14b`. It publishes a 336-byte allocation with tag `0x6e`. If the old-action drop at `0x4c992d6` unwinds, the LSDA lands at `0x4c993a8`, which installs the replacement pointer and tag before resuming unwind; the later normal-path program-pointer increment is not performed on that landing. This is a static ordering observation, not evidence of an exception.

For the non-sentinel input arm in `0x4dd8d50`, the key at frame `+0xf8` is copied to the lookup-key stack area. After account loading, a four-limb balance comparison and a successful call to `0x4dd6b40` for the frame's `+0x138` address, that same key reaches either the owned or borrowed membership call to the already researched `0x488d0b0`. The owned/borrowed selector is context word `+0xe8`; zero passes the pointer at `+0xf0`. A hit writes result status `0x5e` before the new-account checkpoint helper is called. The hit is a membership/collision result; this path does not call the BLAKE2b wrapper.

An alternate input arm of the same new creation FDE builds an address/nonce RLP-shaped preimage. After the nonce helper returns successfully, it encodes the returned 64-bit nonce minus one using zero, one-byte, and big-endian multi-byte cases, hashes the resulting buffer, and takes the final 20 digest bytes. Its entry predicates, alternative environment-provided key and opaque decoder are separate from the selected `0xec` normal arm. The RLP examples in the tests are synthetic projections of these byte windows, not evidence that any particular nonce or address occurred on the node.

### State writes and failure order

| Condition on the selected path | Observed local consequence |
| --- | --- |
| Context depth is greater than `0x400` | Return status `0x11` before the main caller-account load. Equality takes the continuing branch. |
| Caller load returns a byte other than 5 | Copy an error-shaped result with outer tag 4; later nonce and membership steps are bypassed. |
| Four-limb caller amount is less than the requested amount | Return status `0x12` before the nonce helper. |
| Caller nonce is `0xffffffffffffffff` | The nonce helper returns zero; the normal creation arm returns status `0x02` before registry lookup. |
| Earlier decode returns its sentinel, or validation returns a value other than 2 | A separate arm calls the nonce helper and then writes `0x14`; this arm does not test the helper's return before writing that status. |
| Registry membership helper returns nonzero | Return `0x5e` after the earlier successful nonce update and before opening the new-account checkpoint. No local rollback call is made on that hit arm. |
| Registry misses; target hash differs from the retained empty-code constant or target nonce is nonzero | The checkpoint helper calls `0x4dd63d0`, then returns `0x5e`. |
| Target amount addition carries beyond four limbs | The checkpoint helper calls the same rollback boundary, then returns `0x5f`; earlier selected flag/journal writes precede the addition check. |
| Target guard and checked addition succeed | The helper records journal tags 5 and, conditionally, 2; writes the four-limb target amount; writes target nonce 1 when its revision byte exceeds 4; subtracts from the source and appends tag 3. |

The nonce helper first rejects the all-ones word. On the selected successful path it conditionally appends tag 2 and sets flag mask `0x04`, appends tag 4, increments account `+0x60` and returns success. The old nonce has therefore changed before the membership result. The claim is about local order; a surrounding frame or transaction may later revert it.

The checkpoint helper saves its earlier context indices, increments depth, creates a 24-byte empty journal list and checks the target account. It compares two file-backed 16-byte constants with the target's 32-byte code-hash field and also checks the target nonce. Those constants concatenate to the conventional empty-input Keccak digest, which is an observed byte equality; the source field name is inferred. In rollback, context depth is decremented before a separate checked index subtraction. The reverse helper dispatches through the bounded relative-word prefix at `0x6f7034`. Selected tag 4 decrements the keyed nonce, tag 3 reverses the four-limb transfer, tag 5 clears flag mask `0x01` and eventually writes nonce zero, and tag 2 clears mask `0x04` except for the explicit special-key guard when its supplied mode byte is nonzero. Lookup, allocation, dynamic drop and journal-container invariants remain preconditions; these rows do not prove transaction-wide atomicity. The 15 retained table words are a bounded prefix whose next word points outside this FDE, not a claim that all 15 tags are valid inputs.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, original build flags, two-build comparison, normalization masks, helper/data closure, target behavior and whole-ELF equivalence: **not yet implemented or measured**. No target bytes were transplanted into an implementation.

The focused suite passed 44 tests with zero skips. Controls reject corrupted input hashes, instruction windows, transfer kinds/displacements, relocation type/symbol/addend/slot, table entries, section bounds, ambiguous and NOBITS mappings, non-executable FDE ranges and malformed exception records. A separate synthetic Keccak implementation checks the empty digest and a fixed CREATE2 example; projections cover gas/stack boundaries, address/key widths and nonce encoding boundaries. A limb-wise arithmetic projection is checked against independent integer arithmetic over 169 addition and 49 subtraction cases; it is not a target-behavior comparison. The tests neither run nor emulate the captured binary.

## Results and limitations

`summary.json` records 11 selected FDE intervals totaling 10,801 bytes, 72 reviewed windows, 62 selected transfers, 28 selected instruction immediates, 23 selected relative relocations, nine LSDA tables with 88 call-site entries, four selected executor-table words and 15 selected reverse-journal table words. These are explicit selected-corpus counts, not complete CFG, instruction or node coverage. All numbers and generated lists come from authenticated ELF bytes and the shared parsers; synthetic cases are confined to the focused tests.

If the prior mode-2 or mode-5 lineage and membership-helper findings are accepted, the input-derived key equals address 09, the selected frame/callback path is installed, and all preceding guards and helpers take their normal branches, the registry hit produces `0x5e` after the nonce update. No actual preimage yielding address 09, live opcode availability under either revision, callback installation in a running node, or invocation of the address-09 wrapper is established here. The original requested unowned object-returning runtime lookup and the broader first component task remain unfinished. The `evm` component remains 0/4 and no progress gate is requested.

Next question: independently review the earlier executor's action-to-callback binding, then establish which concrete input containers and fork activation rules can reach this salted-address path; a behavioral comparison requires separate execution authorization.
