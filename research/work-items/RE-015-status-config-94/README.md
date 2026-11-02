# RE-015: configured node status-file route and field writers

Node #94's configuration-rooted status handoff reaches a previously unowned serializer whose six ordered fields and error paths can now be reconstructed through the two file-operation boundaries.

- Component ID: `constants`, RE-015; the selected consumer is a node status-record path.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is a lead only and no code is copied from it.
- Claim status: observations below are linked bytes and bounded static control flow; rendered-path and type interpretations are marked as inferences; runtime reachability and I/O remain unresolved.
- Scope included and excluded: eight new #94 FDE extents, the prior caller and path-builder argument-setup and call bytes as boundary context, the two format branches and their local cleanup/error paths. Prior-owned global initialization, formatter, extension predicate, general value formatters, error adapters and file-operation helpers are boundaries. This is not an analysis of the separate visor artifact, even though the node's input name contains `visor`.

## Reproduce

Run from the repository root with the authenticated capture and the repository's shared ELF and FDE readers. The collector uses Python's standard library and those readers; it does not call an external program or execute the capture. To compare two independently generated outputs, substitute two distinct empty writable directories for the placeholders:

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_config_status94 -v
PYTHONHASHSEED=1 TZ=UTC python3 tools/config_status94.py --out <tmp-dir-a>
PYTHONHASHSEED=987 TZ=Pacific/Honolulu python3 tools/config_status94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
python3 tools/config_status94.py --out research/work-items/RE-015-status-config-94
(cd research/work-items/RE-015-status-config-94 && sha256sum -c MANIFEST.sha256)
```

The generator verifies the capture's full size and SHA-256 before parsing, accepts only unique allocated file-backed mappings, uses `tools/elf_index.py` and `tools/fde_extents.py`, and rejects changed selected byte patterns. Environment used: Linux x86-64, Python 3.12.3. The focused tests and two regenerations were also run with a Python-only `PATH`; their outputs matched byte for byte. No whole-repository test suite was run because of the stated memory constraint. The manifest records the README and generated output hashes. No timestamps or machine-specific paths are included in generated records.

## Evidence

All addresses below are unrelocated ELF virtual addresses (VA); corresponding file offsets and exact bytes are in the generated tables. FDE ranges are exclusive at the end and describe unwind ranges, not a complete census or proof of recovered source boundaries. `instructions.tsv` is the result of a restricted byte-pattern length and control-transfer reader on the selected ranges; it is not a general disassembly. Conditional branches into or outside invalid positions, selected LSDA landing boundaries, and the ELF unwind-index/FDE binding are checked. `branches.tsv` and `transfers.tsv` include all conditional branches and direct or indirect transfers within these ranges. `cfg.tsv` is an overapproximation that admits both outcomes and assumes calls return; it does not prove that a branch is feasible.

| New role | FDE start | FDE end | Bytes |
| --- | --- | --- | ---: |
| JSON record writer | `0x276cd60` | `0x276cf9f` | 575 |
| Binary record writer | `0x276cfa0` | `0x276d2ad` | 781 |
| JSON object close | `0x27b1280` | `0x27b13c1` | 321 |
| Binary optional float | `0x27b25e0` | `0x27b2717` | 311 |
| Format and file route | `0x28eb6a0` | `0x28eb8f1` | 593 |
| JSON optional height | `0x295c660` | `0x295c7bd` | 349 |
| JSON time-field wrapper | `0x2965820` | `0x29658c5` | 165 |
| JSON optional float | `0x296c640` | `0x296c7ae` | 366 |

### Configuration to file-route boundary

Existing `RE-001-snapshot-admission-94` already records the call from `0x220c11e` to `0x25ae060`, so that path-builder FDE is **not** selected or exported as a complete body; only the short handoff windows are retained. The selected boundary bytes at `0x220c0eb..0x220c123` build the record, store a zero qword at its `+0x10`, pass name descriptor `0x569dc78`, and pass Location-shaped descriptor `0x569dc88`. The first descriptor has a relative relocation to `0x208cf0` and length 16: `visor_abci_state`. The second has source tail `l1/src/abci/engine.rs:259:41`; the complete path's byte length and SHA-256, rather than its absolute prefix, are retained in `path.json`.

Only the boundary handoff is recorded: at `0x25ae0c9` the path builder reads slot `0x576e928`, whose relative relocation points to cell `0x577b288`, and uses cell `+0x18` after checking `+0x50`. The cell's own relative relocation binds its initializer pointer to previously studied `0x164ff00`; prior work connects that initializer to `/cham`, `/static_config`, and the `NvTestnet` fallback. At `0x25ae111` the boundary refers to the complete formatting template `c0 12 /hyperliquid_data/ c0 01 . c0 00`, and at `0x25ae139` it calls the newly selected file route `0x28eb6a0`. The prior-owned path builder's whole behavior and its name-to-extension decision are outside this packet. No concrete rendered filename, runtime global root, or name-discriminator outcome is claimed.

On the shown normal handoff, the original Location-shaped third argument is passed to the file route as its fourth argument, and the file route passes it to the second file step as its fifth argument. The existing [`bridge-state-json-94`](../bridge-state-json-94/README.md) identifies the separately owned extension predicate at `0x144a3e0`; its semantics are not re-established by claiming its body here. This packet instead closes the new file-route body and its record writers from their entry onward.

### Ordered fields and representation boundaries

Both selected writers reference these full name bytes, with the same order and input offsets. The binary writer emits the field names when its named-mode flag is set; the file route sets that flag. `fields.tsv` retains each name pointer, length and writer call.

| Order | Name | Input offset | JSON call boundary | Binary value call boundary |
| ---: | --- | --- | --- | --- |
| 0 | `initial_height` | `+0x20` | `0x2958170` | `0x25ac0d0` |
| 1 | `height` | `+0x28` | `0x2958170` | `0x25ac0d0` |
| 2 | `scheduled_freeze_height` | `+0x00` | `0x295c660` | `0x25ac0d0` on the selected value arm |
| 3 | `consensus_time` | `+0x30` | `0x29967e0` | `0x1dfca40` |
| 4 | `wall_clock_time` | `+0x3c` | `0x2965820` | `0x1dfca40` |
| 5 | `reference_lag` | `+0x10` | `0x296c640` | `0x27b25e0` |

After each of the six JSON value calls, the selected nonzero-result branch goes to common return `0x276cf22`, before the object-close call; `fields.tsv` records each individual branch. The binary writer's corresponding result branches and both successors are also retained. For the optional-height value arm, equality with result tag 2 takes the continuation; the other successor returns the error-shaped words. The two time fields and lag field use their separately recorded success-sentinel checks. These observations do not assign behavior to the external value writers.

The JSON height helper tests bit 0 of the first word and writes `null` when it is clear; the binary height writer compares the low 32 bits with 1 and writes byte `0xc0` on the other arm. The JSON lag helper checks whether its first byte is zero; absent and nonfinite values both write `null`. For a present finite value it delegates formatting through slot `0x576f478`. The magnitude mask `0x7fffffffffffffff` and infinity threshold `0x7ff0000000000000` are read from its instructions. The binary lag helper tests bit 0 and writes `0xc0` when clear, otherwise delegates the floating-point value. In the concrete caller the observed zero at `+0x10` selects JSON `null` if the record is passed unchanged to that writer.

The two encoders' comparisons differ for noncanonical tag words: for example, height tag 3 takes the JSON value arm but the binary nil arm; lag byte 2 takes the JSON present arm but the binary nil arm. These are static controls for the individual instruction predicates, not an assertion that invalid values are valid Rust enum representations or arise during normal execution. The meaning and units of `reference_lag`, finite-number text, and complete time formatting remain boundaries.

### Selected normal and failure gates

| Site and condition | Observed result |
| --- | --- |
| `0x28eb6e3`: full path equals `/dev/null` | Return zero before either serializer and both file-operation calls. The concrete rendered path is unresolved. |
| `0x28eb6f7`: extension predicate returns zero | Allocate an initial 128-byte buffer, set the indent descriptor to two spaces, and call JSON writer `0x276cd60`. |
| `0x28eb6f7`: extension predicate returns nonzero | Build a binary writer with options word `0x01000400`, including its named-mode byte, and call `0x276cfa0`. |
| `0x28eb753`: binary result differs from `0x8000000000000004` | Release the owned buffer if needed and call the existing binary-error adapter `0x28eb970`; do not enter either file step. |
| `0x28eb7d3`: JSON writer returns nonzero, or `0x28eb7e9` sees the signed-minimum buffer sentinel | Take the JSON error route through existing adapter `0x28eb900`; do not enter either file step. |
| `0x28eb803`: first file-step result is nonzero | Skip the second step and release the buffer if needed. The first slot `0x576ea68` binds to `0x144c180`. |
| `0x28eb803`: first file-step result is zero | Pass the buffer, path and prior caller's location-shaped argument to slot `0x576f670`, bound to `0x144c560`; return its result after cleanup. |
| `0x28eb776`: initial JSON-buffer allocation fails | Enter the allocation-failure call at `0x28eb8ad`. |
| `0x276cd73`: JSON nesting counter is all ones | Enter the overflow diagnostic instead of incrementing it. |
| `0x27b12aa`: JSON close sees depth zero | Enter the separate close-depth diagnostic. |

The selected file-route FDE has an LSDA; `exception-sites.tsv` retains its five protected ranges, landing addresses and action indices. The action/type encodings are not interpreted. The protected file-step range lands at `0x28eb8d3` for buffer cleanup before resuming unwinding. No operating-system write, runtime exception or successful cleanup is asserted.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker settings, two-build result, raw or normalized binary comparison, masks, external helper closure, runtime fixtures, vtable/data closure and whole-ELF equivalence: not yet implemented or measured. The selected bytes and relocation records are preserved without normalization. The controls execute a Python model of selected predicates against binary-extracted constants; they are not target execution or a Rust equivalence oracle.

## Results and limitations

`summary.json` records 8 selected FDEs, 3,461 bytes, 865 length-decoded instructions, 82 conditional branches, 102 transfers, 16 relocations, 32 fixed byte contracts, 15 structural reachability queries and 5 LSDA call-site entries. These are denominators for the selected ranges only. The focused suite passed 18 tests with zero skips, including wrong digest, altered field bytes and instructions, bad branch destinations, duplicate or malformed relocation, invalid or NOBITS mappings, canonical and noncanonical tags, and finite/infinite/NaN boundaries. Two independent Python-only regenerations matched. Artifact verification and catalogue checking passed.

No constants progress gate is requested: the component remains 0/4. The path builder, concrete extension and global root values, runtime reachability, filesystem effects, complete semantics of the external file helpers and formatter, exact finite-number and time text, every possible caller and the separate #115/visor artifacts remain unresolved. Next question: can the already-owned file-operation boundaries be connected to an independently implemented status record without assuming successful I/O or unchanged inputs?
