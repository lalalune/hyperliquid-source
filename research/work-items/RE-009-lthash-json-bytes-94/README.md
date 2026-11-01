# RE-009: lattice checkpoint JSON byte-value helpers

The selected node #94 checkpoint reader treats an escape-free quoted `hash` payload as bytes rather than hexadecimal pairs, so a reconstruction must compare the decoded byte length with 2,048 before copying the bytes into the restored lattice value.

- Component ID: RE-009, storage/state roots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is a lead, not implementation source.
- Claim status: static observations on the selected scanner, array and result-dispatch instructions; type and format roles are inferences from the earlier checkpoint reader; full input-language behavior remains unresolved.
- Scope included and excluded: three previously unexamined helper FDEs, the byte-class table and relocation edges, selected branch and failure decisions, and contextual instruction windows from the previously documented fixed-byte reader. Excluded: re-analysis of that reader as a whole, the existing escape decoder, the existing general numeric parser, other snapshot representations and releases, live data, and execution.

## Reproduce

From the repository root, with CPython 3.12.3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/lthash_json_bytes94.py --out research/work-items/RE-009-lthash-json-bytes-94
python3 -m unittest tests.test_lthash_json_bytes94
(cd research/work-items/RE-009-lthash-json-bytes-94 && sha256sum -c MANIFEST.sha256)
```

`evidence.json` is the generated record. The generator verifies the complete binary SHA-256 first and imports the repository's ELF and FDE parsers. It reads relocation addends, instruction windows and the 256-byte table directly from the file; it neither invokes binutils nor executes the target. GNU objdump 2.42 was used for manual inspection only. For a repeat check, run the generator with two different output directories and compare their contents byte for byte. No input other than the retained binary and repository parsers is used.

## Evidence

Coordinates are linked ELF virtual addresses, with zero load base and exclusive FDE ends. The FDEs describe unwind extents; manual instruction inspection supports the selected paths, not a complete function-boundary or control-flow proof. The contextual reader was previously mapped in `research/work-items/RE-009-lthash-read-94`; its enclosing function is not a new claim here. The new FDEs are:

| Role on this selected route | Start | End |
| --- | --- | --- |
| JSON array element and separator state | `0x302ae70` | `0x302afdd` |
| byte-valued numeric result adapter | `0x30596e0` | `0x305985e` |
| quoted byte scanner | `0x4ebfd80` | `0x4ec0072` |

The earlier packet binds the `hash` field to a fixed 2,048-byte reader and leaves quoted-string conversion open. The contextual call at `0x309486a` uses relocation slot `0x5775508`, whose RELATIVE addend is `0x4ebfd80`. After a non-error result, the context compares the returned length at `0x309495d` to `0x800` and branches on inequality; the equal arm copies the returned bytes. The selected array call at `0x30948f6` reaches `0x302ae70`, which calls `0x30596e0` at `0x302af7d`. These site windows are included solely to verify the connection to the previously established reader.

### Quoted value

The scanner reads the table at `0x7caac8` through RELATIVE slot `0x57770a8`. The generated record includes every table byte and the resulting 256-way branch classification. At `0x4ebfdec` it consults that table. A zero entry continues scanning; for a nonzero entry, quote selects the closing path, backslash selects the escape helper, and the other marked bytes continue scanning. The table marks 34 values: 0 through 31, quote and backslash. This is a scanner-level observation, not a claim about validation by an enclosing parser.

When a closing quote is found with an empty scratch buffer, the return path stores a pointer to the original span and its byte count (`0x4ebff1c` onward). It does not perform hexadecimal conversion on that span. With accumulated scratch bytes, the scanner copies the final span and returns the scratch pointer and total byte count (`0x4ebfecf` onward). On backslash, it appends the preceding span and calls the previously studied escape helper; a nonzero helper result takes the error return and zero resumes scanning. Input exhaustion takes a separate error route. Allocation and integer-overflow exits are also present; their effects are not simulated. The escape helper's internals are outside this packet.

For example, the selected escape-free scan of two ASCII `0` bytes followed by the closing quote returns two payload bytes, not one decoded zero byte. At the higher reader's selected length check, 2,047 and 2,049 returned bytes take the unequal branch; 2,048 take the equal branch. These examples are a static model of the pinned instructions, not target executions or complete checkpoint fixtures.

### Array elements and failures

The array helper's pinned whitespace mask `0x100002600` selects byte values 9, 10, 13 and 32. Its local state distinguishes the first element from later ones. A closing bracket can terminate before the first value or after a completed value; a comma before the first value and a closing bracket immediately after a comma take distinct error-construction paths. An end-of-input condition also has its own route. The `evidence.json` branch table records destinations rather than assuming error type names.

After a value token, the helper calls the numeric adapter. The adapter delegates actual numeric lexing to a previously studied callee, then accepts result tags 1 or 2 only when the returned unsigned payload is less than 256, storing its low byte. Tag 3 takes an error path; other result tags and values at least 256 go to diagnostic paths. Thus these results are conditional on that callee's tag and do not by themselves establish which textual spellings produce any particular tag. The outer fixed-byte reader separately checks element count and its own failure paths as described by the prior packet.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiled comparison, normalization masks, runtime comparison, actual checkpoint fixtures and full helper/relocation closure: not yet measured. The generator's small scanner and result-tag models are evidence controls, not an executable replacement for the node. Seven focused unittest methods cover the authenticated input, all 256 scanner classifications, quote and escape dispatch, 2,047/2,048/2,049 modeled lengths, result-tag values 0, 1, 255 and 256, changed instruction and table bytes, wrong digest, NOBITS and unmapped addresses, a missing relocation, and altered relocation type and addend. No test executes the captured binary.

## Results and limitations

The generated record contains 3 selected FDE extents, 10 pinned instruction windows, 12 decoded branch destinations, 2 selected relocations, and 256 byte classifications. These are selected evidence, not whole-module coverage. Seven focused tests passed. The result does not establish full JSON conformance, all escape or number behavior, on-disk occurrence, a version compatibility rule, or that any real checkpoint loads. No full-scope milestone gate is requested. Next question: independently recover the complete string-escape and numeric-callee contracts at this specific call context, then compare synthetic checkpoint fixtures in a separately authorized offline execution harness.
