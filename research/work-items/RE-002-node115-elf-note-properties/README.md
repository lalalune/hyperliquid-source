# RE-002: node #115 ELF note-section program identity

- Component ID: `constants` (Global configuration: static network/build configuration and naming), recorded under the RE-002 build-provenance allocation.
- Target release and full SHA-256: Linux x86-64 `hl-node` #115, 105,896,032 bytes, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: job base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No upstream source revision is claimed for these note bytes.
- Claim status: observation for every byte, address, count and section coordinate below; the ABI-tag and build-id readings are recorded separately as inferences in `evidence.json`.
- Scope included and excluded: included is every `SHT_NOTE` section header in the 33-section table of the pinned target, with its index, type, flags, address, file offset, size, raw bytes, and each contained note header plus descriptor bytes. Excluded are program headers and any `PT_NOTE` segment count, `.comment`, compiler identity, linker flags, `.text` windows, target execution and any reconstruction gate.

## Question

Which program-identity notes does the retained Linux x86-64 node #115 ELF declare in its `SHT_NOTE` sections, and what do those pinned bytes constrain for a deterministic source rebuild?

## Reproduce

From the repository root with the pinned capture materialised:

```sh
python3 test-results/slop-workbench/packet-2af706de9171.py
```

The verifier authenticates `artifacts/node/115/hl-node` in place against the pinned SHA-256 and the recorded 105,896,032-byte size, parses the ELF64 header and section header table, selects every section whose `sh_type` is 7 (`SHT_NOTE`), and prints each section's coordinates, raw bytes, note headers and descriptor bytes before it asserts that the saved packet records the same values.

The retained exploratory run of this verifier is proof 0, command `python3 -B test-results/slop-workbench/foundation_elf_note_properties.py`, exit 1, ending with the assertion `packet evidence not yet written: README.md, evidence.json, frames.txt, property-window.txt, note-excerpt.txt`. That run is the source of every value below; it is recorded partial progress while the packet was incomplete, not a passing validation.

Tooling: Python 3 standard library only (`hashlib`, `struct`, `pathlib`). No network, no execution of the target, no copy of the target. The target is read in place only.

## Evidence

Recorded from the pinned bytes. Address and file offset are equal in both sections as read:

| Section | Index | Type | Flags | Address | File offset | Size | Note count |
| --- | ---: | ---: | --- | --- | --- | ---: | ---: |
| `.note.ABI-tag` | 2 | 7 | `0x2` | `0x2fc` | `0x2fc` | 32 | 1 |
| `.note.gnu.build-id` | 3 | 7 | `0x2` | `0x31c` | `0x31c` | 36 | 1 |

Recorded totals: `section_count=33`, `note_section_count=2`, `derived_sections=.note.ABI-tag,.note.gnu.build-id`. No other section header in that table carries `sh_type` 7.

`.note.ABI-tag` raw section bytes, 32 bytes:

```
040000001000000001000000474e550000000000030000000200000000000000
```

One note: name `GNU`, `namesz` 4, `descsz` 16, type 1, descriptor `00000000030000000200000000000000`.

`.note.gnu.build-id` raw section bytes, 36 bytes:

```
040000001400000003000000474e5500ac2880fcda5e49007a8e4fb1ea6aa7dd1b2eae01
```

One note: name `GNU`, `namesz` 4, `descsz` 20, type 3, descriptor `ac2880fcda5e49007a8e4fb1ea6aa7dd1b2eae01`.

Derived build-id value: `ac2880fcda5e49007a8e4fb1ea6aa7dd1b2eae01`, descriptor length 20.

No note of type 5 (`NT_GNU_PROPERTY_TYPE_0`) appears in either note section, and no `.note.gnu.property` section header exists in the recorded 33-section table. `evidence.json` therefore records `gnu_property_note_present: false` with that basis, and `property-window.txt` records the same observed absence with `property_entry_count=0`, rather than an invented ISA, IBT or SHSTK property bitmap.

`frames.txt` and `note-excerpt.txt` repeat the values above. This packet claims no `.text` window, so no FDE/CIE extent is recorded here; the "frames" of this question are the two note sections, identified by section index.

## Inferences, kept apart from the bytes

- `sh_flags` `0x2` is the ELF `SHF_ALLOC` bit, so both note sections belong to the loaded image.
- Type 1 with the four little-endian words 0, 3, 2, 0 reads as the GNU ABI tag for OS Linux with a minimum kernel of 3.2.0 under the documented `NT_GNU_ABI_TAG` layout. This is an inference from the recorded descriptor bytes, not an executed check.
- Type 3 with a 20-byte descriptor is `NT_GNU_BUILD_ID`. Those bytes are link-time output, so an independently built node is not expected to reproduce them byte for byte.

## Implementation and comparison

Not yet implemented or measured for this question: no Rust path, no Cargo.lock, no compiler or linker flags, no two-build result. This packet claims no `.text` window, so it contributes no reconstructed first-party component bytes and cannot overlap a claimed text window; a window shared with an upstream dependency would need that dependency identity, and none is claimed here. No `compiler`, `linker` or `crate graph` conclusion is drawn from these two note sections.

## Results and limitations

Machine-readable result: `evidence.json` in this directory records the same section coordinates, raw bytes, note headers, descriptor bytes, counts and build-id as the tables above. The packet files named in `MANIFEST.sha256` are the current saved bytes.

Limits: static read of two `SHT_NOTE` sections of the pinned target. No program header or `PT_NOTE` segment count, no `.comment`, no compiler identity, no linker flags, no byte search outside the two note sections, no target execution, no behaviour claim and no reconstruction or progress gate. The observed absence of a property note is bounded to the section headers recorded here. These two note sections do not close build provenance: toolchain version, crate graph, compiler/linker flags and the deterministic build plan remain open RE-002 fields.

Next question: which `PT_NOTE` program-header segment covers these two note sections, and does any other loaded segment carry a note-shaped record?
