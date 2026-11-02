# RE-009: lattice checkpoint JSON value writer

The selected node #94 checkpoint JSON writer emits each lattice hash as an array of 2,048 unsigned decimal byte values, and emits its two associated counters as decimal integers, enabling a reconstruction of the nested value without inventing a hexadecimal or base64 encoding.

- Component ID: RE-009, storage and state roots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is a lead only.
- Claim status: observation for selected instructions, constants, data and calls; inference for the resulting JSON value and field roles; unresolved for actual filesystem output and cross-release compatibility.
- Scope included and excluded: four previously unanalysed writer and formatting FDEs, selected field-call contexts from the earlier writer, byte-array formatting and selected failure paths. Excludes reanalysis of the previously mapped enclosing writer, its top-level selection predicate, allocator implementation, every possible failure in generic helpers, real checkpoint fixtures, MessagePack, target execution and other releases.

## Reproduce

From the repository root with Python 3.12.3, standard library and the shared `tools/elf_index.py` and `tools/fde_extents.py` parsers:

```sh
python3 tools/artifacts.py verify
python3 tools/lattice_json_write94.py --out research/work-items/RE-009-lattice-json-write-94
python3 -m unittest tests.test_lattice_json_write94
python3 tools/catalogue.py --check
(cd research/work-items/RE-009-lattice-json-write-94 && sha256sum -c MANIFEST.sha256)
```

For a separate output directory, use `python3 tools/lattice_json_write94.py --out <tmp-dir>` and compare the two generated files with the packet. The generator verifies the binary digest before parsing, checks indexed FDEs and complete body hashes, reads file-backed sections only, and decodes pinned relative calls and RIP-relative data references. It runs no external program and does not run the target. GNU objdump 2.42 was used only for manual inspection. A second generation under a different hash seed and time zone was byte-identical.

Generated evidence SHA-256: `records.json` `2c8236cb1617865cd4a534d03a837cf6839d549577b60a4433f56c1dc4c5195b`; `byte-decimal.tsv` `fc783c77bd59c8dcf384c69991e59dd3457073ec29ca75edba4c080fb747de90`. The TSV is a static model of the byte formatter, not target execution.

## Evidence

All addresses are linked ELF virtual addresses; FDE ends are exclusive. An FDE is an unwind-described extent and does not alone prove all entry points or cold paths. `records.json` contains complete selected-body hashes, raw instruction windows, relative-call edges and selected conditional targets. Only the named paths and windows were inspected; this is not a whole-program analysis.

Prior work `RE-009B-lt-hashes-format` maps the surrounding checkpoint writer, its JSON branch, and three top-level values but leaves each nested value unresolved. Prior work `RE-009-lthash-read-94` identifies nested reader fields and a fixed-size array. The contextual instruction windows here connect those results to four new writer bodies; no new claim is made for the earlier enclosing function.

| Contextual call site | Input to selected child | Field literal | Selected target |
| --- | --- | --- | --- |
| `0x37eb8aa` | value pointer `+0x800` | `n_elements` | `0x3c8c100` |
| `0x37eb8d8` | value pointer `+0x808` | `n_bytes` | `0x3c8c100` |
| `0x37eb902` | value pointer `+0x0` | `hash` | `0x3c83850` |

The field names come from three RIP-relative literals, and the two qword offsets and calls are checked in the same instruction windows. The names and order agree with the earlier reader; the interpretation as lattice counters follows that evidence, not an asserted source type.

| New selected FDE | Selected behavior |
| --- | --- |
| `0x3c8c100..0x3c8c1fd` | Calls the existing key formatter, loads a qword, appends `: `, invokes the decimal formatter and copies its output. A key-state value of 1 branches to a non-returning diagnostic route; buffer-capacity shortfalls call a growth helper. |
| `0x3c1d4d0..0x3c1d612` | Formats the unsigned qword using a 20-byte scratch span, a two-digit lookup table and groups of 10,000. The reciprocal multiply and shift implement the quotient used by this path. |
| `0x3c83850..0x3c838e7` | Calls the key formatter, appends `: `, and calls the byte-array writer with length `0x800`. Key-state 1 branches to the diagnostic route; insufficient output capacity calls growth. |
| `0x3bebf60..0x3bec2dd` | Writes `[` and `]`, iterates the supplied byte span, emits each as an unsigned decimal number, separates subsequent values with comma/newline and writes indentation. Zero length takes a separate close-array branch; incrementing an all-ones nesting depth takes a diagnostic branch. |

Selected decision and failure branches, with destinations decoded from the instruction bytes:

| Test at site | Taken destination | Bounded observation |
| --- | --- | --- |
| `0x3c83864`, `0x3c8c11a` | `0x3c838b0`, `0x3c8c195` | Key helper returns state 1; enter diagnostic call path. |
| `0x3bebf76` | `0x3bec2d0` | Nesting depth equals all-ones before increment; enter diagnostic call path. |
| `0x3bebfab` | `0x3bec22b` | Length is zero; skip the element loop and close the array. |
| `0x3bec08c`, `0x3bec0c7` | `0x3bec0c0`, `0x3bec0e0` | Select the one-, two-, or three-digit byte formatting path. |
| `0x3bec13d` | `0x3bebfd0` | More input bytes remain; continue the element loop. |
| `0x3bebf92`, `0x3bebfd7`, `0x3bebffa` | `0x3bec255`, `0x3bec16a`, `0x3bec194` | Insufficient buffer capacity for an opening bracket, first newline, or comma/newline; enter growth paths. |
| `0x3bec039`, `0x3bec105`, `0x3bec1c5`, `0x3bec232` | `0x3bec05f`, `0x3bec145`, `0x3bec2ac`, `0x3bec28b` | Insufficient buffer capacity for indentation, decimal digits, closing newline, or closing bracket; enter growth paths. |
| `0x3c8c135`, `0x3c8c165`, `0x3c8387b` | `0x3c8c1ae`, `0x3c8c1d5`, `0x3c838c9` | Field output lacks capacity for the colon/space or formatted scalar; enter growth paths. |

The byte writer's `movzx` load selects one byte; values below 10 use one digit, values 10 through 99 use a two-byte table entry, and values 100 through 255 use a leading digit plus a two-byte table entry. The shared table at `0x5b988d` contains the ASCII pairs `00` through `99` in order. The comparison and branch destinations are byte-decoded, while the arithmetic and instruction boundaries were checked manually. As examples, input bytes 0, 9, 10, 99, 100 and 255 yield decimal tokens `0`, `9`, `10`, `99`, `100` and `255`. All 256 model results are in `byte-decimal.tsv`.

The output is therefore inferred to have the logical nested form `{"n_elements": N, "n_bytes": B, "hash": [H0, H1, ...]}`, with 2,048 elements in the selected call. The writer uses pretty-print whitespace; this logical example intentionally does not claim exact indentation or full file bytes. Success is conditional on the enclosing writer reaching these calls and on its helper calls succeeding. The capacity and diagnostic destinations do not establish recovery or retry behavior.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiler, build, compiled-byte comparison, normalization masks, complete helper closure and runtime fixture: not yet measured. No captured program, chain data or network was used. Tests check the model against independent decimal text over every byte, 65,536 consecutive qword values, 10,000 deterministic 64-bit values and selected decimal/64-bit boundaries; they also reject a wrong digest, a changed instruction, rehashed changes to a body and digit table, invalid integer ranges and non-file-backed or out-of-range addresses. These are extractor and static-model controls, not native execution.

## Results and limitations

Four new indexed FDE extents, five selected direct calls, 17 selected conditional targets and all 256 byte values are recorded. Eight focused test methods passed; two independently regenerated outputs matched byte for byte. The evidence does not establish which format the path predicate selects in a live invocation, exact file bytes, filesystem durability, or compatibility with other releases. No full-scope milestone gate is requested.

Next question: recover a non-overlapping path-selection implementation and test the actual nested JSON against an authorized offline fixture.
