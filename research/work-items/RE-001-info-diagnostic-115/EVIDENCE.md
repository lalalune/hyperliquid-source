# RE-001-info-diagnostic-115: where is one info_server source diagnostic referenced?

- Component ID: info-api; bounded RE-001 coordinate research, not RE-012 behavior recovery.
- Target: node #115, `artifacts/node/115/hl-node`, 105896032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
  No inferred reference implementation was read or copied for this packet.
- Claim status: observed static coordinates; interpreting the record as a Rust
  source Location is an inference. The enclosing function's semantics are unresolved.
- Included: one relocation-backed source record, two selected native instruction
  references, and their containing unwind extent. Excluded: exhaustive references,
  callees, request/response behavior, runtime reachability and implementation equivalence.

## Reproduce

From the repository root with the pinned artifact materialized and Python 3 plus
GNU binutils available:

```sh
python3 research/work-items/RE-001-info-diagnostic-115/proof.py
python3 -m unittest discover -s tests -p test_node115_info_coordinates.py -v
```

The first command authenticates the complete file before static analysis and
regenerates adjacent `proof.json`. It invokes exactly:

```sh
readelf --debug-dump=frames-interp artifacts/node/115/hl-node
objdump -d --start-address=0x29691a0 --stop-address=0x2969331 artifacts/node/115/hl-node
```

Observed tools: GNU readelf and objdump 2.40. `proof.json` records exact commands,
coordinates, bytes and tool identities. `SCOPED-RUN.json` records the actual test
command, result, environment and authored input hashes. No target execution,
networking, signing, Ghidra analysis, installation or model-backed inference is used.
The only standalone proof side effect is rewriting its JSON output; tests read the ELF.

## Evidence

All addresses below are link-time ELF virtual addresses unless marked file offset;
no runtime load bias is assumed. File mappings are independently decoded from
file-backed PT_LOAD segments and code references require executable mappings.

| Item | Observed coordinate / value |
| --- | --- |
| Source token | `info_server/src/abci_state_info_handler.rs` |
| Source bytes | VA and file offset `0x432b83` |
| Source-record fields | length 42, line 664, column 120 |
| Record | VA `0x6441ad8`, file offset `0x643fad8` |
| Relocation | RELA file offset `0x62958`, destination `0x6441ad8`, type 8 (`R_X86_64_RELATIVE`), symbol 0, addend `0x432b83` |
| Reference A | VA `0x29692a8`, file offset `0x29682a8`, bytes `48 8d 3d 29 88 ad 03` |
| Reference B | VA `0x29692b5`, file offset `0x29682b5`, bytes `48 8d 3d 1c 88 ad 03` |
| Containing FDE | `[0x29691a0, 0x2969331)` |

The 24-byte record is `00000000000000002a000000000000009802000078000000`.
Its raw pointer is zero; the relocation supplies the source address. Both selected
instructions decode as RIP-relative LEAs to the record. Native objdump decoding
from the unwind start corroborates instruction alignment, rather than treating
arbitrary matching bytes as instructions. Native readelf supplies the unique FDE
containing each selected instruction. This is a range-limited result, not a full
binary analysis or a source-level function-name recovery.

## Implementation and comparison

`proof.py` and the scoped tests are independently authored Python standard-library
code. No Rust equivalent, two-build comparison, normalization mask, ABI reconstruction,
helper closure or semantic comparator is implemented or measured. No unlicensed
inferred source is included. The packet contains minimal factual byte observations,
not a captured binary, transplanted implementation or full disassembly.

The scoped file exercises the genuine pinned ELF and native tools. Mutation controls
reject a wrong digest/truncation, record pointer/length/line/column changes, source
path corruption, missing/duplicate/wrong-type/wrong-symbol/wrong-addend relocations,
each selected LEA's opcode/displacement corruption, and invalid/ambiguous mappings.
Low-level mutations bypass authentication deliberately to test the relevant structural
checks, rather than obtaining only a checksum rejection. Separate textual-parser
controls reject missing, changed, duplicated or overlapping FDEs and missing,
misaligned, duplicated, wrong-byte or wrong-mnemonic native instructions.

## Results and limitations

The implementation run passed 11/11 unittest methods, including actual native FDE
and alignment verification. The selected comparison denominator is two references:
2/2 resolve to this record and share the stated containing FDE; neither count is
an inventory of all references or all info-api functions. Required repository checks
and independent reconstruction are reported separately by validation; scoped success
alone does not establish them.

No completion gate is requested; component catalogues and executable upstream code
are unchanged. Node #94 and visor are not covered. The diagnostic record does not
prove semantic ownership, helper identity, a reachable request path, runtime behavior,
protocol compatibility or equivalence. A next research question, not answered here,
is which actual callers reach this extent and under what input conditions.
