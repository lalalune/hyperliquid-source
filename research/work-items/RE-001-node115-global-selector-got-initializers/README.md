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
  word, to code addresses `0x14c4570` and `0x14c4020`, respectively.
- Those code addresses begin FDE extents of 465 and 1,351 bytes. The first
  contains one indirect compare route; the second contains four. Each loads
  the GOT entry at `0x64dfb50`, whose `R_X86_64_GLOB_DAT` resolves to
  `memcmp@GLIBC_2.2.5`, then calls the loaded register with `EDX=20`. Each
  route advances the compared record pointer by `0x14` and converts the
  `memcmp` result sign into `-1`, `0`, or `1`. This establishes fixed-width
  comparison behavior in these two code targets, not the source type or the
  meaning of either containing object.
- A full GNU `objdump -d -w -Mintel` scan finds 36 direct RIP-relative
  64-bit loads from these slots: 18 for each slot. Each instruction's encoded
  displacement is independently checked against its reported target. The
  sites fall in 12 unique FDE extents, with exactly one containing FDE per
  site.
- `xref-instructions.txt` retains the decoded load instruction, its address,
  slot, and FDE extent. `records.json` retains all 36 rows and the ELF
  relocation/object bytes. The two `0x14c*.objdump.txt` exports and
  `memcmp-relocation.txt` retain the exact callback and import evidence.

## Limits

An FDE extent is not proof of a function boundary. The callback analysis is
limited to the two selected code targets; it does not establish whether
pointer values can be changed through indirect stores, what selector policy
applies beyond the earlier packet, source-level names, runtime configuration
precedence, or the semantic meaning of the objects. The `.bss` range is not
treated as initialized file data. No captured code was executed or emulated,
and no network, signing, or chain action occurred. All component gates remain
false.

## Reproduction

Requirements: Python 3.10+, GNU binutils (`objdump` and `readelf`), and the
pinned repository artifact. From the repository root:

```sh
python3 research/work-items/RE-001-node115-global-selector-got-initializers/collect.py \
  --output work/global-selector --check
python3 -m unittest discover -s tests \
  -p test_node115_global_selector_got.py -v
```

The collector checks the complete target digest before invoking native tools,
independently parses ELF sections, RELA entries and unwind FDE extents, and
cross-checks each selected instruction's RIP-relative target. It verifies the
two callback extents byte-for-byte against GNU disassembly, the import symbol,
20-byte call lengths, `0x14` strides and sign-conversion instruction counts.
The test also corrupts a private in-memory copy of the artifact and confirms
the digest gate refuses it before creating output. The collector and tests do
not execute the captured node.

## Evidence

- `records.json`: digest-bound relocation, object-byte and xref records.
- `xref-instructions.txt`: all 36 direct loads and their containing FDE
  extents.
- `14c4570.objdump.txt`, `14c4020.objdump.txt` and
  `memcmp-relocation.txt`: retained callback and imported-symbol evidence.
- `tool-versions.json`: GNU objdump and readelf versions.
- `collect.py`: deterministic static collector and byte/section/FDE checks.
