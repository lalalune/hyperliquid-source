# RE-017: scheduled-cancel state loading and root-input serialization

The node #94 JSON and MessagePack state readers converge on a scheduled-cancel value layout whose `t` and `n` presence rules also control a named state field's app-hash input, enabling a reconstruction to preserve null, duplicate-field and omission behavior on this selected path.

- Component ID: `abci`, RE-017; bounded loader-to-state-root-input question.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` used only for leads. No reference implementation was copied.
- Claim status: byte ranges, relative destinations and data are observations; type, field and lifecycle interpretations are conditional inferences below. Model rows are synthetic, not captured execution.
- Scope included and excluded: selected, previously unowned scheduled-cancel map/value readers for both formats, two lanes of their root-input writers and bounded connections to prior work. The original state-loader GOT and calls, old outer reader/serializer bodies, mutation handlers, all other root inputs, whole-block execution, node #115 and visor are excluded.

## Reproduce

Run from the repository root with CPython 3.12.3, its standard library and the target artifact present. Both comparison directories should start empty. The tool authenticates the input before parsing and reads it without executing it.

```sh
python3 tools/artifacts.py verify
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_cancel_root94.py --out work/cancel-a
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_cancel_root94.py --out work/cancel-b
diff -r work/cancel-a work/cancel-b
diff -r -x README.md -x MANIFEST.sha256 work/cancel-a research/work-items/RE-017-cancel-root-94
python3 -m unittest tests.test_abci_cancel_root94
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-cancel-root-94 && sha256sum -c MANIFEST.sha256)
```

The generated files are `functions.tsv`, `windows.tsv`, `edges.tsv`, `branches.tsv`, `references.tsv`, `literals.tsv`, `inline-text.tsv`, `dispatch.tsv`, `relocation.tsv`, `indirect.tsv`, `writer-cases.tsv`, `reader-cases.tsv`, `fixarray-cases.tsv` and `summary.json`. The manifest covers those files and this README. The generator imports `tools/elf_index.py` and `tools/fde_extents.py`, excludes SHT_NOBITS sections, requires unique file-backed mappings, ties each selected FDE to its unwind-index entry, and decodes only the selected x86 byte forms. It applies no normalization masks and invokes no external program. GNU objdump 2.42 was used only for bounded human inspection. Generator and tests also run with a Python-only PATH; the tests require the binary and do not skip. There is no target execution, networking, chain access or key use.

## Evidence

Addresses are linked ELF virtual addresses, with load base zero. Files record file offsets separately; for example `0x30b8fe0` maps to file offset `0x30b7fe0`. `functions.tsv` gives exclusive FDE ends, CIE/FDE/LSDA addresses and raw FDE-range hashes. An FDE is an unwind-described range, not proof of complete function boundaries. Selected windows are unmasked and some cut instruction boundaries; the listed branches and edges decode complete, pinned instructions. Tables contain selected sites, not a whole-node census. All role names are local analysis labels.

### Boundaries and new paths

The prior [state-link packet](../RE-017-abci-state-link-94/README.md) links a `state.rs` Location to the loader. The prior [format packet](../RE-019-rmp-json-loader-94/README.md) identifies its `.rmp` and JSON arms. The earlier JSON Exchange-field packet (PR #1369 in the supplied snapshot) owns the outer reader and dispatch, leaving nested values open. The existing [app-hash builder packet](../RE-009-app-hash-builder-94/README.md) records row 17's field capture and closure but leaves its serializer open. These are context, not newly owned functions. Connections to earlier bodies are marked `prior-boundary` in the generated tables; no original state-loader GOT or call site is claimed here.

| Path | Selected linked VAs | Observation |
| --- | --- | --- |
| JSON map boundary | `0x2fe8112` -> `0x363eef0` | The previously studied Exchange visitor calls the newly studied field map reader. A non-success child result follows the separately pinned branch at `0x2fe8127`. |
| JSON object map | `0x363eef0` -> `0x301d7f0` / `0x3022400` -> `0x30b8fe0` | Selected object keys and values lead to the same nested value reader. `0x324f600` supplies a 20-byte key buffer to an external decoder. |
| JSON pair array | `0x363eef0` -> `0x36c4290` -> `0x3030830` -> `0x30b8fe0` | The alternate array route also reaches the value reader; `0x30485b0` supplies a 20-byte buffer to `0x3093d90`, which invokes the same decoder as the object-key path. |
| MessagePack boundary | `0x2e0e6aa` -> `0x2bfe6c0` -> `0x2ab4a60`; `0x2abb86f` -> `0x2de8130` | The selected format arm reaches a prior field visitor. Its duplicate branch refers to the 24-byte `user_to_scheduled_cancel` label; its nonduplicate arm calls the new map decoder. |
| MessagePack map | `0x2de8130` -> `0x3679c50` -> `0x2c710c0` | The selected fixed-map arm calls the value reader and `0x2a72b70` for each key. |
| MessagePack pair array | `0x2de8130` -> `0x36af9e0` -> `0x2d3afe0` -> `0x2c710c0` | The selected fixed-array arm reaches the same value reader; the pair reader sets up a 20-byte key buffer. |
| Named writer | `0x275b2b7` -> `0x27b3660` -> `0x25edcb0` | The prior serializer passes its base plus `0x39a8`. The new wrapper conditionally emits `user_to_scheduled_cancel` and transfers to the low map writer. |
| App-hash row 17 | `0x28168a0` -> `0x25edcb0`; `0x4ae4ae0` -> `0x46042b0` | Previously identified low/shared closure bodies invoke the new map writers. The low builder's row-17 capture is base plus `0x39a8`; see the prior closure table. |

The MessagePack map loop passes the four-byte literal `User` to `0x2a72b70`; its length check selects the ordinary path, which supplies a 20-byte buffer to `0x2bd0ea0`. The pair-array key path calls that same buffer decoder. The exact byte and text grammar accepted by that helper remains unresolved. Both JSON map forms and both selected MessagePack map forms call the existing insertion helper `0x339e370`; the shown nonzero-result arms construct the inline text `duplicate key`. `inline-text.tsv` reconstructs the four strings from their overlapping immediate stores. Child read errors, key errors and insertion/allocate failures take distinct pinned exits. These observations do not establish all map formats, all key encodings, allocator behavior or sorting.

The JSON reader's 33-entry signed table is rooted at `0x59224c`: the `[` entry reaches the pair-array path and `{` reaches the object path. For MessagePack, the selected direct-marker path reads a byte, takes the fixed-map route for `0x80..0x8f` and the fixed-array route for `0x90..0x9f`. Other marker representations and any normalized parser-state entry paths are outside this marker claim. Both routes check the decoder nesting state; a non-success child is forwarded rather than treated as a map.

### Nested value: normal and error decisions

The JSON value reader `0x30b8fe0` accepts selected map and array routes. Its invalid-type path references a vtable at `0x56dd050`; the relocation at slot `0x56dd068` points to `0x3432030`, which refers to the literal `struct ScheduledCancel`. The MessagePack value reader is `0x2c710c0`. Their selected field decisions are:

| Condition | JSON observation | MessagePack observation |
| --- | --- | --- |
| `t` first occurrence | Calls `0x3b81700`; exact ASCII `null` returns a zero option dword, otherwise delegates to the Time helper. The seen flag is set on successful return. | Calls `0x2a6e990`; nil marker `0xc0` returns success tag 9 and a zero option dword, otherwise delegates with the literal `Time`. The seen flag is set on successful return. |
| `n` first occurrence | Calls `0x2fe4ce0`, which delegates number decoding and rejects the shown negative result arm. | Calls the existing integer helper `0x2a65d30`; tag 9 is the selected success result. |
| missing field | On the map-completion path, absent `t` gets a zero option dword and absent `n` a zero u64. | The map-completion path similarly selects zero for the unseen tag and count. |
| duplicate `t` or `n` | Separate seen flags reach `t` and `n` duplicate-field paths before a second value is read. | Separate seen flags reach the corresponding literal-labeled duplicate paths before a second value is read. |
| unknown key / child failure | Unknown keys and integer/time parsing are delegated; shown non-success results go to error paths. | Unknown keys are delegated to `0x2ddabf0`; selected non-9 child results take error paths. |

On the selected successful JSON result, the count u64 is stored at result `+0x08`, option dword at `+0x10`, and an opaque eight-byte tail at `+0x14`. The MessagePack success staging and copy show the same relative payload layout after the result tag. The packet does not assert that the tail is initialized when its option is absent. A successful explicit null still marks `t` seen, so another `t` takes the duplicate path even though the value dword is zero; likewise `n=0` does not erase the `n` seen flag. `reader-cases.tsv` illustrates this with already-decoded events, not JSON or MessagePack test fixtures.

For the MessagePack value's selected fixarray path, the low nibble gives a length. Conditional on the nesting check and any child returning success, length 0 defaults both values, length 1 delegates `t` and defaults `n`, length 2 delegates both, and lengths greater than 2 take a non-success tag-4 remainder branch. `fixarray-cases.tsv` enumerates all 16 marker lengths as a static model; it does not model child data or prove the final application-level error text.

### Root-input writer and state changes

Both lanes collect the map and write a sequence of pairs. The low chain is `0x25edcb0` -> `0x1e33450` -> `0x1debef0` -> generic `0x28e49c0` or direct `0x28e4b20`; the shared chain is `0x46042b0` -> `0x4409880` -> `0x43c8990` -> generic `0x4c64730` or direct `0x4c64890`. Collection and primitive encoders are explicit helper boundaries. The pair writers have selected child-error exits, and the direct pair path writes the two-element prefix `0x92`. The shared direct pair path also calls newly studied key writer `0x43f56b0`. After the selected buffer-flush path, it calls through slot `0x5773120` with a 20-byte input, output capacity 42 and mode zero, then passes the returned span to `0x4aeb630`. The slot's relocation targets `0x29ed380`, whose [independent prefixed-hex proof](../RE-005-prefixed-hex-rust-94/README.md) gives lowercase `0x`-prefixed hex under valid nonoverlapping buffers and sufficient capacity. Under those conditions the selected key span is therefore `0x` followed by 40 lowercase hex characters. The writer has separate buffer-header, buffered-byte and final-string failure branches. The packet does not establish map iteration order or the complete byte stream.

The four value writers load a u64 at payload `+0` and an option dword at `+8`. Their field count is `(n != 0) + (t_tag != 0)`. They visit `t` first when its tag is nonzero and `n` second when the count is nonzero. Named-mode branches use the one-byte keys `t` and `n`; the direct path writes `a1 74` and `a1 6e`, respectively, and delegates each corresponding value. `writer-cases.tsv` covers zero, one and maximum storage-width bit patterns as an arithmetic model; not every bit pattern is asserted to be a valid Time. The closure boundaries set writer configuration before calling the map writers. Different configuration paths and child encodings remain unresolved.

On the shared direct path the `t` writer calls newly studied `0x43e35d0`. It formats the first component through slot `0x576f560`, writes the byte `T` through a vtable `+0x20` call, formats the second through slot `0x576f568`, and passes the buffer to `0x4aeb630`. `indirect.tsv` and `relocation.tsv` bind the two slots to addends `0x151f240` and `0x15204a0`. Each of the three formatting operations has a nonzero-result branch to the same diagnostic path, which contains `a Display implementation returned an error unexpectedly` and ends in `ud2`. Other formatter internals and exact date, subsecond and timezone bytes are not established.

The existing [schedule-cancel admission study](../fees-schedule-cancel-gate-94/README.md) and [firing study](../RE-006-scheduled-cancel-fire-94/README.md) independently identify a user map at base `+0x39a8` and its 24-byte value with count and date at `+0` and `+8`. The former describes action admission and its failure order; the latter describes firing, saturating increment, clearing the date, and day reset. Those function bodies are not reanalysed here. **Conditional composition:** if the parsed field, the mutated map and the row-17 captured field are the same live object, and no later write changes the fields before serialization, then firing produces a nonzero count and a zero date and the selected writer omits `t` while including `n`. A reset of a retained armed entry sets the count to zero, so the selected writer omits `n` and can include `t`. This is a reconstruction consequence of the prior mutation evidence and the new writer branches, not proof that these lifecycle steps ran or that a final hash changed.

### Inferences and unresolved connections

The field-name literal, prior field-dispatch label, compatible value layouts and shared `+0x39a8` offset support identifying these as views of scheduled-cancel state. They do not prove object identity across decoding, materialization, mutation and hashing. In particular, the decoded aggregate and a later builder argument may be different copies or may have intervening writes; the shared builder's capture is not independently identified by offset here. The `Time` tag layout and the meaning of count are supported by the cited prior mutation packet, while detailed Time and integer grammars remain helper boundaries. The task scheduler, full begin/action/end-block order, exact map ordering, resource failures, all remaining state-root fields and final digest are not closed.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo build scope, compiler/linker flags, two-build comparison, raw and normalized binary comparison, helper and call-target closure, vtable/data closure and whole-ELF comparison: **not yet measured**. The type-formatter relocation, two Time-helper relocations and prefixed-hex relocation are checked; they are not a complete relocation closure. The selected source bytes are unmasked. The case tables are static interpretations of selected branches, not target-derived snapshots or node executions.

## Results and limitations

`summary.json` reports 34 selected FDE ranges, 105 byte windows, 81 selected relative transfers, 115 conditional branches, 19 RIP-relative references, 16 literal ranges, 33 JSON dispatch entries and four relocations. The three synthetic tables contain 9 writer, 9 reader-event and 16 fixarray cases. These denominators describe this packet only, not function or component coverage. The focused suite has 23 passing tests and no skips; controls corrupt the artifact digest, instructions, branch/edge targets, inline text, data, dispatch table, relocation and address mappings, including SHT_NOBITS. Independent regeneration under different hash seeds and time zones is byte-identical. Artifact verification and catalogue checking pass; the repository-wide suite was not run under the stated memory constraint.

No progress gate is requested: ABCI remains 0/4. The requested full begin/action/end-block and state-root reconstruction is not complete. Next question: trace a previously unowned result/materialization handoff that proves, or disproves, whether the decoded scheduled-cancel map is the same instance subsequently captured by the low builder, including intervening writes.
