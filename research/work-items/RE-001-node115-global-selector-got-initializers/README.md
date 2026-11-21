# RE-001: bind two node115 global selector slots to relocated objects

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository base: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`.
Component/task: Global configuration (`constants`), bounded RE-001 evidence
for issue [#3909](https://github.com/lalalune/hyperliquid-source/issues/3909).

This packet extends the merged
[`RE-001-node115-global-source-handoff`](../RE-001-node115-global-source-handoff/README.md).
That packet records the selector condition and the two slots, but leaves the
pointed-to objects and wider consumers unnamed. This packet answers a narrower
follow-up: what ELF relocation initializes each slot, where does it point, and
what direct code references to those slots are present in the pinned image?

## Observations

- Both slots lie in `.got`. `.rela.dyn` contains an `R_X86_64_RELATIVE`
  relocation at `0x64dfff8` with addend `0x64efc80`, and another at
  `0x64e0000` with addend `0x64efcb0`.
- Both addends identify 48-byte file-backed objects in `.data`. Their retained
  raw bytes are in `records.json`; each has a relative relocation at its first
  word, to code addresses `0x14c4570` and `0x14c4020`, respectively. The
  relocation records establish addresses, not the meaning of either object or
  code target.
- A full GNU `objdump -d -w -Mintel` scan finds 36 direct RIP-relative
  64-bit loads from these slots: 18 for each slot. Each instruction's encoded
  displacement is independently checked against its reported target. The
  sites fall in 12 unique FDE extents, with exactly one containing FDE per
  site.
- `xref-instructions.txt` retains the decoded load instruction, its address,
  slot, and FDE extent. `records.json` retains all 36 rows and the ELF
  relocation/object bytes.

## Limits

An FDE extent is not proof of a function boundary. This is an inventory of
direct disassembled references, not a complete dynamic dataflow proof. It does
not establish whether pointer values can be changed through indirect stores,
what selector policy applies beyond the earlier packet, source-level names,
runtime configuration precedence, or the semantic meaning of the objects.
The `.bss` range is not treated as initialized file data. No captured code was
executed or emulated, and no network, signing, or chain action occurred.
All component gates remain false.

## Reproduction

Requirements: Python 3.10+, GNU binutils (`objdump`), and the pinned repository
artifact. From the repository root:

```sh
python3 research/work-items/RE-001-node115-global-selector-got-initializers/collect.py \
  --output work/global-selector --check
python3 -m unittest discover -s tests \
  -p test_node115_global_selector_got.py -v
```

The collector checks the complete target digest before invoking `objdump`,
independently parses ELF sections, RELA entries and unwind FDE extents, and
cross-checks every selected instruction's RIP-relative target. The test also
corrupts a private in-memory copy of the artifact and confirms the digest gate
refuses it before creating output. The collector and tests do not execute the
captured node.

## Evidence

- `records.json`: digest-bound relocation, object-byte and xref records.
- `xref-instructions.txt`: all 36 direct loads and their containing FDE
  extents.
- `tool-versions.json`: GNU objdump version used to produce the retained scan.
- `collect.py`: deterministic static collector and byte/section/FDE checks.
