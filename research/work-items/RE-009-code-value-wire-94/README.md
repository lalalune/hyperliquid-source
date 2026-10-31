# RE-009-code-value-wire-94: what bytes does node #94 store for a HyperEVM code value?

- **Component ID:** storage (`db/src/db_hub.rs`, `l1/src/evm/evm_db.rs`).
- **Target release and full SHA-256:** Linux x86-64 **hl-node #94**,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- **Source commit / reference commit:** branch cut from `1f8c67c63ca4`; can1357 reference
  submodule `999556f6e0a4`, used as leads only.
- **Claim status:** *observation* for the variant tags and names, the field names, their order and
  source offsets, the jump table form, the single-entry map gate, the `order` value compare and the
  capacity panic. *Inference* for the crate names (revm, bitvec, rmp-serde), the meaning of the
  fields, and error kind 13. *Unresolved*: see "Results and limitations".
- **Scope included:** the map-mode writer `0x3bf8bb0` and its payload writers, the reader entry
  `0x2a6afe0`, its two variant paths, the `LegacyAnalyzed` array-form element order, and the bit
  vector reader down to assembly.
  **Excluded:** the JSON writer `0x3bf8d20`, list element writers, `Eof` and `Eip7702` readers,
  runtime data, and any #115 or visor claim.

**Bounded question.** The writer `0x37d2000` encodes one value through `0x358c870`. What exact
bytes come out, and what does the reader refuse?

**Answer.** A value is a one-entry MessagePack map from the variant name to its payload:

| tag | name | payload |
| --- | --- | --- |
| 0 | `LegacyRaw` | bin of the code |
| 1 | `LegacyAnalyzed` | map: `bytecode` bin, `original_len` uint, `jump_table` |
| 2 | `Eof` | map: `header`, `body`, `raw`; the value holds an `Arc` |
| 3 | `Eip7702` | map: `delegated_address` bin8 of 20, `version` uint, `raw` bin |

`jump_table` is not a bin. It is a four-field map, and `data` is an **array of integers**, one per
byte, so a byte of 0x80 or more takes two bytes on disk:

```text
84 a5 "order" b3 "bitvec::order::Lsb0"
   a4 "head"  82 a5 "width" 08 a5 "index" <head>
   a4 "bits"  <bit count>
   a4 "data"  <array header> <uint>...
```

A 5-byte code with a 12-bit table `ff ff` ends in `a4 "bits" 0c a4 "data" 92 cc ff 0f`: the top four
bits of the last byte are masked off before writing.

The reader refuses a map with any other entry count and a bare variant name. A wrong `order` string
takes the reject branch. `bits` above the byte capacity of `data` is a **panic**, not an error
value.

## Reproduce

Working directory: repository root. No external program is run and the binary is never executed.

```sh
python3 tools/artifacts.py verify
python3 tools/code_value_wire.py --out research/work-items/RE-009-code-value-wire-94
python3 -m unittest tests.test_code_value_wire
sha256sum -c research/work-items/RE-009-code-value-wire-94/MANIFEST.sha256
```

The manifest check runs with the folder as working directory. The tool needs Python 3 with the
standard library plus `tools/elf_index.py` and `tools/fde_extents.py`, takes about 10 s, and
refuses any binary with a different digest.

Generated files: `code-value-wire.json` (variants, fields, functions, 100 rip pins, 138 byte pins,
4 range pins, examples, the sweep) and `code-value-fields.tsv` (29 field rows). Every number comes
from ELF bytes read with `struct`, so the output does not depend on a binutils version. objdump was
used only to read code by hand and to draft the pin list, and no output of it is parsed by the tool.

## Evidence

Coordinates are ELF virtual addresses; FDE ends are exclusive. Function extents are in the JSON.

### From the database write to the writer

`0x37d2303` calls the encoder `0x358c870`. The encoder computes `code + 0xe9`, compares with 4
(`0x358c88a`, `0x358c88e`), stores flag bytes `00 04 00 01` at serializer `+0x8` (`0x358c8b6`), then
calls `0x3bf8bb0` (`0x358c8d3`). So serializer `+0xa` is 0 (binary) and `+0xb` is 1 (named fields).
The getter side calls the decoder `0x2a6afe0` at `0x37d1502`. The writer stores the enum name
`Bytecode` at `0x3bf8bd9`.

### Variants

The writer reads the tag at value `+0` (`0x3bf8bc2`) and dispatches through the relative table
`0x5b7404`; the payload starts at value `+8` (`0x3bf8bc5`). The reader's name match returns the
same indexes: `0x3bfac5b`, `0x3bfacc7`, `0x3bfabf5`, `0x3bfacfd` store index 0, 1, 2, 3 beside
status 9.

| tag | name | writer arm | payload writer | map reader | bare reader |
| --- | --- | --- | --- | --- | --- |
| 0 | `LegacyRaw` | `0x3bf8bd9` | `0x3246260` | `0x2be5e50` | `0x2aec8a0` |
| 1 | `LegacyAnalyzed` | `0x3bf8c9e` | `0x39057c0` | `0x2bf3510` | `0x2aec9a0` |
| 2 | `Eof` | `0x3bf8c07` | `0x3904d60` | `0x3444830` | `0x2aec830` |
| 3 | `Eip7702` | `0x3bf8c5a` | `0x3904490` | `0x2d0ab90` | `0x2aecfa0` |

Each arm writes map header 1 (`0x35981d0`), then the name. Arm 2 loads a pointer and adds `0x10`
(`0x3bf8c43`, `0x3bf8c46`), which skips two `Arc` counters.

### Fields

`code-value-fields.tsv` has all 29 rows with name, source offset, form and callee. Each row is
checked three ways: the `lea` reaches the name, the immediate is its length, and the call reaches
the callee. The stored fields of the two live forms:

| owner | position | name | offset | form |
| --- | --- | --- | --- | --- |
| `LegacyAnalyzed` | 0 | `bytecode` | 0x00 | bin |
| `LegacyAnalyzed` | 1 | `original_len` | 0x28 | uint |
| `LegacyAnalyzed` | 2 | `jump_table` | 0x20 | bit vector map |
| `Eip7702` | 0 | `delegated_address` | 0x20 | bin8 of 20 bytes |
| `Eip7702` | 1 | `version` | 0x34 | uint |
| `Eip7702` | 2 | `raw` | 0x00 | bin |

Write order differs from offset order in both. `Bytes` keeps its pointer at `+8` and length at
`+0x10` (`0x3a08bc6`, `0x3a08bca`).

### Jump table

`0x323f840` first compares the newtype name with `_ExtStruct` (`0x323f857..0x323f878`); `JumpTable`
has length 9, so that arm is not taken. It reads the bit vector through the `Arc`: pointer at
`+0x10`, encoded length at `+0x18` (`0x323f881`, `0x323f885`). `index` is the low three bits
(`0x323fa2f`, `0x323fa32`) and `bits` is the length shifted right by 3 (`0x323fa76`, `0x323fa79`).

`data` goes through `0x3814330`, then an array header (`0x323fb4e`) and one call per element to the
integer writer (`0x323fc4b`, `0x323fca1`). The other loop branch is off: the slot at `+0x58` is set
to the `i64::MIN` marker at `0x323fb68` and the loop tests that marker at `0x323fc8f`.

`bit_domain` models the selector `0x3814330`, whose bytes are pinned by hash along with three
builders. Sweeping head 0 and bits 0..=65536 gives 1 empty, 8192 whole-byte and 57344 masked-tail
spans, and the element count equals `(bits + 7) >> 3` at every point. The tail builder `0x38142d0`
keeps the low `tail` bits of the last byte.

### Reader

`0x2a6afe0` tests for `map32`, `map16` and `fixmap` markers. Lengths must be 1 (`0x2a6b03b`,
`0x2a6b0a4`, `0x2a6b122`); otherwise it stores error tag 4 with the length (`0x2a6b127`). Other
markers go to `0x3bfa8a0`. All four bare arms store kind 13 and build an error, so a plain variant
name is rejected even for a valid name.

In `LegacyAnalyzed` array form the elements are read as bytes (`0x2bf3a0e`), length (`0x2bf3adf`),
jump table (`0x2bf3ba9`), the same order as the map form.

`0x34449a0` calls `0x2ca6440` and places the result in a new 0x28-byte `Arc` with both counters 1.
The map loop in `0x2ca6440` dispatches through table `0x4cc514`:

| index | arm | reader | set in the assembly state |
| --- | --- | --- | --- |
| 0 | `0x2ca6a11` | `0x2df3fd0` | presence at `+0x2a` |
| 1 | `0x2ca6ac1` | `0x2aeb250` | presence at `+0x28`, index at `+0x29` |
| 2 | `0x2ca6a45` | `0x2a65ca0` | presence at `+0`, value at `+8` |
| 3 | `0x2ca6a73` | `0x2b377d0` | capacity, pointer, length at `+0x10`, `+0x18`, `+0x20` |

The `0x2df3fd0` string arm requires length 19 (`0x2df422e`) and compares two 16-byte windows at
offsets 0 and 3 against the constant `0x5b44b2` (`0x2df4238..0x2df4261`), which covers all 19 bytes.

`0x2aeae30` reports a missing `order`, `head`, `bits` or `data` by name. It then computes
`capacity * 8 - head`, saturating at 0 (`0x2aeaeee..0x2aeaefb`), and if `bits` is larger it branches
(`0x2aeaf06`) to a panic with the text `bit-vector capacity exceeded:` (`0x2aeb13d`, `0x2aeb150`).

### Differences from the reference

`l1/evm` and `db` in the reference have no `Bytecode`, jump table or bit vector type, so this form
is absent there rather than different.

## Implementation and comparison

not yet implemented. There is no Rust path and no comparison against a real database. The value
builders in the tool are evidence checks, not an implementation.

## Results and limitations

- Tests: 42 in `tests/test_code_value_wire.py`, all pass. Negative controls flip every rip pin's
  opcode, change every target, flip the last byte of every byte pin and range, alter the jump
  tables, names, lengths and callees, and test a wrong digest, `.bss` and unmapped addresses.
- `bit_domain` is a hand transliteration of pinned bytes, not an execution of them. Heads other
  than 0 are selected but their builders are not modelled. Head 0 is the only form the examples use;
  no constructor was read to show it is the only stored form.
- The array-form element order was read for `LegacyAnalyzed`; its map-form loop was not. The tool
  shows the stored map form is written in that order, and does not show the reader needs it.
- Unresolved: the integer path of the variant identifier reader `0x2b36910`, the `width` and `index`
  checks in `0x2aeb250`, and whether `data` capacity can exceed its length.
- `Eof` fields are pinned as a layout. No row was shown to hold this variant. `0x32166c0`,
  `0x3212200` and `0x3217910` are listed as callees; their element forms were not read.
- Which codes reach this encoder is not shown here beyond the gate; `0x37d2303` is the call edge.
- This is a static reading. No database file was inspected, and no gate is requested.

Next question: what do `0x2d0ab90` and the map loop of `0x2bf3510` accept, and does anything rebuild
the jump table instead of trusting the stored one?
