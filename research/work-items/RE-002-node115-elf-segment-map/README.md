# RE-002: node #115 ELF load map and .text VA-to-file-offset translation

- Component ID: RE-002 (build provenance), prerequisite for RE-001 (function map)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Claim status: observation (static bytes only)
- Scope included and excluded: included is the ELF program-header and section-header
  parse of the pinned target and the resulting VA-to-file-offset translation.
  Excluded is any execution of the target, any behavior claim, any first-party
  component byte credit, any acceptance gate and any upstream dependency code.

## Question

For the pinned Linux x86-64 node #115 ELF, what is the exact virtual-address (VA)
to file-offset translation for each `PT_LOAD` program header and for the `.text`
section?

This is a prerequisite for reading any recorded target window (an FDE range, a
caller excerpt, a data record) from the pinned bytes: a recorded VA can only be
read once the mapping from that VA to a file offset is established from the
target ELF itself. It is not a reconstruction claim and it advances no gate.

## Reproduce

The checker reads `artifacts/node/115/hl-node` as bytes only. It never executes
or copies the target.

```sh
python3 -B tools/foundation_node115_elf_segment_map.py
python3 -B tools/foundation_node115_elf_segment_map.py --check research/work-items/RE-002-node115-elf-segment-map
python3 -m unittest discover -s tests -p test_foundation_node115_elf_segment_map.py -v
```

Tool versions: Python 3 standard library only (`struct`, `hashlib`, `json`).
No disassembler, no Ghidra, no network. Input identity is the target SHA-256
above; the checker recomputes it and refuses a different file.

## Evidence

All values below are observations from the pinned target bytes, recorded in
`load-map-excerpt.txt` and `text-window-excerpt.txt`.

Program headers: the target has four `PT_LOAD` segments (indices 2, 3, 4, 5).

| index | flags | p_offset | p_vaddr | p_filesz | p_memsz | p_align |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 4 | 0x0 | 0x0 | 21070420 | 21070420 | 0x1000 |
| 3 | 5 | 0x1418300 | 0x1419300 | 83724448 | 83724448 | 0x1000 |
| 4 | 6 | 0x63f0ba0 | 0x63f2ba0 | 1031808 | 1033312 | 0x1000 |
| 5 | 6 | 0x64eca20 | 0x64efa20 | 66536 | 2330372 | 0x1000 |

`.text` section: address `0x1419300`, file offset `0x1418300`, size 83719936,
`sh_addralign` 256, inside load segment 3.

Entry point: VA `0x1419300`, file offset `0x1418300`.

Observed relationships:

- Every load segment satisfies `p_filesz <= p_memsz` and
  `p_offset + p_filesz <= file size` (105896032).
- Each load segment's `p_vaddr` translates back to its own `p_offset`.
- `.text` and the entry point both translate to file offset `0x1418300`, which is
  the `p_offset` of load segment 3.
- Load segment 3 ends at `0x1418300 + 83724448 = 0x63f0ba0`, exactly the
  `p_offset` of segment 4.
- Both writable segments carry a zero-fill tail: segment 4 has
  `p_memsz - p_filesz = 1,504` bytes and segment 5 has `2,263,836` bytes.

## Implementation and comparison

`tools/foundation_node115_elf_segment_map.py` parses the ELF64 header, the
program header table and the section header table, then derives the load map,
the `.text` record and the entry record. `va_to_offset` translates a VA through
the file-backed part of a `PT_LOAD` and raises `ElfFormatError` for a VA in a
zero-fill tail or outside every segment.

`tests/test_foundation_node115_elf_segment_map.py` exercises the real checker:
it derives the map from the pinned target, checks the translation round trips,
and runs the checker against a constructed synthetic ELF whose expected map is
known. Negative controls cover `p_filesz > p_memsz`, a load past the file
extent, `.text` outside every load, a truncated section table, bad magic, wrong
class and byte order, and a short header. The synthetic ELF is a test fixture
only; it is not derived from the target.

No Rust implementation, no build and no byte comparison is claimed here.

## Results and limitations

Observed: the four-segment load map, the `.text` record and the entry record
above, all re-derived from the pinned bytes by the committed checker.

Limits:

- Static byte evidence only. The target was never executed and no runtime
  behavior is claimed.
- This packet records no single address window and claims no first-party
  component bytes, no dependency bytes and no acceptance gate.
- `evidence.json` is not yet present in this packet; the checker's `--check`
  mode fails until it is written, which is expected progress.
- The full `make test` suite was not run locally and no CI result is claimed.

Next question: with the VA-to-file-offset map fixed, read one authenticated
FDE-derived function body from the pinned bytes and record its exact extent and
call targets (RE-001).
