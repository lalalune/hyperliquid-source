# RE-001: node #115 vault-transfer diagnostic coordinates

- Component: `vaults`; bounded additional RE-001 function mapping, not vault accounting.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Repository baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Claim status: static observation. Source-path meaning is a diagnostic attribution, not recovered source or proven function semantics.
- Includes one diagnostic/Location/instruction/FDE association. Excludes helper behavior, ownership, share accounting, permission checks, callers, other releases and gate completion.

## Reproduce

From repository root with the pinned node input materialized, Python 3.10+ and GNU objdump:

```sh
python3 research/work-items/RE-001-node115-vault-diagnostic/verify.py
python3 -m unittest discover -s tests -p test_node115_vault_diagnostic_coordinates.py -v
```

The first command emits the observations in `replay.json`; the second runs nine real-input checks. Exact observed versions, commands, exit codes and SHA-256 values for the verifier, tests and retained outputs are in `RESULTS.json`. Initial discovery used GNU readelf/objdump 2.40 and Python 3.11.11. The initial native command is recorded in `replay.json`; `selected.objdump.txt` retains its one bounded excerpt. Its output hash is historical provenance, not a cross-version correctness requirement. No captured target was executed; tools only read static bytes. No network or reference-source implementation is required.

## Evidence

The source token is `l1/src/action/vault_transfer.rs`. A 24-byte Location at VA `0x643bb20` contains the unrelocated pointer zero, source length 31, line 27 and column 18. Its unique `R_X86_64_RELATIVE` relocation (type 8, symbol zero) supplies the source VA. The seven bytes `4c 8d 1d 3d f4 bf 03` at VA `0x283c6dc` decode as a RIP-relative LEA targeting that Location. Disassembling from the independently decoded unwind start verifies instruction alignment rather than accepting an arbitrary byte-string hit.

The selected FDE's backward CIE pointer resolves inside `.eh_frame`; the verifier decodes CIE version 1, `zR` augmentation and `0x1b` PC-relative signed-four-byte encoding. The result is the half-open VA extent `[0x283c6b0, 0x283c768)`, containing the LEA. The FDE section-relative offset is `0xb4424`; it is a pinned coordinate, not an exhaustive frame scanner. PT_LOAD segments translate VAs to file offsets; those coordinates must not be conflated.

| File-coordinate field | Offset |
| --- | --- |
| `source_file_offset` | `0x431977` |
| `location_file_offset` | `0x6439b20` |
| `relocation_file_offset` | `0x5ac78` |
| `instruction_file_offset` | `0x283b6dc` |
| `fde_file_offset` | `0xd5b2fc` |
| `cie_file_offset` | `0xca6ed8` |

## Implementation and comparison

`verify.py` is independently authored Python standard-library code plus a bounded native objdump read. It uses no copied inferred reference source. No Rust replacement, semantic equivalence, raw/normalized implementation comparison, helper closure or ABI recovery has been implemented/measured.

Eight controls each change a real target byte in memory: source token, Location line, relocation type, LEA opcode, LEA displacement, FDE start, FDE range and CIE version. Each invokes structural validation without the digest guard, so rejection proves the corresponding structural assertion is exercised rather than merely checksum rejection. The ninth test authenticates the unchanged target digest and native instruction alignment. Source/relocation/FDE coordinate observations agree for **1/1 selected binding**; this is not a denominator for all vault functions, all source diagnostics or any task completion percentage.

## Results and limitations

The recorded implementation replay and nine scoped tests pass. Repository-wide checks are separate and must be reported from independent validation; no full-suite or hosted-CI success is claimed here. The analysis is deliberately limited to one function extent and one source record. All component/progress gates remain unchanged and incomplete.

Prior exact overlap review excluded PR #2220's different `[0x44ae810,0x44af2e1)` extent and retained the separate #2287 exclusion; bounded `vault_transfer`/`283c6b0` PR searches had no matches. Those checks are not exhaustive proof of novelty. Live selection/publication clearance is still required.

Next question: what target-grounded caller and helper evidence would be needed before assigning behavior to this diagnostic-bearing function? That work is not performed or claimed here.
