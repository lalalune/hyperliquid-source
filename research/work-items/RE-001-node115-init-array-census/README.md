# RE-001: node #115 `.init_array` / `.fini_array` constructor slot census and RELATIVE relocation coverage

- Component ID: foundation / static-initializer tables (RE-001 #115 function map).
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: bound to base commit
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; the pinned target at
  `artifacts/node/115/hl-node` is read in place and is never executed or copied.
- Claim status: **observation**. Every value below is read from the pinned
  target bytes. Labels such as "constructor" or "destructor" are the ELF table
  names, not recovered source semantics.
- Scope included and excluded: included is the slot census of the two arrays,
  their addresses and file offsets, and their coverage by `R_X86_64_RELATIVE`
  entries in `.rela.dyn`. Excluded is what any entry function does, any source
  or Rust symbol identity, any call graph, and any runtime behaviour.

## Exact question

Which slots does the authenticated node #115 ELF record in its `.init_array`
and `.fini_array` tables, at which virtual addresses and file offsets, what does
`.rela.dyn` bind each slot to, and how many slots are covered by an
`R_X86_64_RELATIVE` relocation?

## Reproduce

From the repository root with the pinned capture materialised, Python 3.10+:

```sh
python3 -B tools/foundation_init_array_census.py
python3 -m unittest discover -s tests -p test_foundation_init_array_census.py -v
```

The checker reads `artifacts/node/115/hl-node` in place, asserts the pinned
digest and size before using any byte, parses the ELF64 section table,
`.rela.dyn`, `.init_array`, `.fini_array` and `.eh_frame`, prints the derived
facts, and then compares them with this packet's `evidence.json`, `init-array.txt`
and `frames.txt`. While those data files are still being written it exits
nonzero on the missing records; that is expected progress, not a target result.
The committed test loads the same checker module and runs it against the saved
packet.

No captured executable, emulator, network, chain action or signing path is
used. The target is not copied into `test-results/`.

## Evidence

Coordinates are ELF virtual addresses (VA) and file offsets into the pinned
file. Section headers as derived from the bytes:

| Section | Index | Type | Flags | Address (VA) | File offset | Size | Entry size |
| --- | ---: | ---: | --- | --- | --- | ---: | ---: |
| `.init_array` | 22 | 14 (`SHT_INIT_ARRAY`) | `0x200003` | `0x63f36c8` | `0x63f16c8` | 1344 | 0 |
| `.fini_array` | 21 | 15 (`SHT_FINI_ARRAY`) | `0x3` | `0x63f36c0` | `0x63f16c0` | 8 | 8 |
| `.rela.dyn` | 9 | 4 (`SHT_RELA`) | `0x2` | `0x6be8` | `0x6be8` | 1457352 | 24 |

`.rela.dyn` holds **60,723** whole 24-byte records; **59,534** distinct target
addresses carry an `R_X86_64_RELATIVE` relocation.

Array census: `.init_array` is 1344 bytes = **168** 8-byte slots and
`.fini_array` is 8 bytes = **1** slot. Every one of the 168 init slots and the
single fini slot carries an `R_X86_64_RELATIVE` relocation (`covered_by_relative`
168 and 1), so all stored slot words read `0x0` and the effective entry address
comes from the relocation addend.

Recorded slots (VA is the slot address; the addend is the entry the loader binds):

| Slot | Slot VA | Slot word | `R_X86_64_RELATIVE` addend |
| --- | --- | --- | --- |
| `.init_array[0]` | `0x63f36c8` | `0x0` | `0x5ca55c0` |
| `.init_array[1]` | `0x63f36d0` | `0x0` | `0x14193e0` |
| `.init_array[2]` | `0x63f36d8` | `0x0` | `0x5d20090` |
| `.init_array[3]` | `0x63f36e0` | `0x0` | `0x5d41fa0` |
| `.init_array[4]` | `0x63f36e8` | `0x0` | `0x5d483b0` |
| `.init_array[5]` | `0x63f36f0` | `0x0` | `0x5d83f80` |
| `.init_array[6]` | `0x63f36f8` | `0x0` | `0x5d979f0` |
| `.init_array[7]` | `0x63f3700` | `0x0` | `0x5da48f0` |
| `.init_array[8]` | `0x63f3708` | `0x0` | `0x5da8610` |
| `.init_array[9]` | `0x63f3710` | `0x0` | `0x5daf1b0` |
| `.init_array[10]` | `0x63f3718` | `0x0` | `0x5db5ee0` |
| `.init_array[11]` | `0x63f3720` | `0x0` | `0x5dc23d0` |
| `.init_array[164]` | `0x63f3be8` | `0x0` | `0x620a480` |
| `.init_array[165]` | `0x63f3bf0` | `0x0` | `0x620a4c0` |
| `.init_array[166]` | `0x63f3bf8` | `0x0` | `0x620b470` |
| `.init_array[167]` | `0x63f3c00` | `0x0` | `0x635f320` |
| `.fini_array[0]` | `0x63f36c0` | `0x0` | `0x14193a0` |

Slots 12 through 163 are not expanded in this README; the complete slot list is
recorded in `init-array.txt`, and the per-slot FDE extent mapping derived from
`.eh_frame` is recorded in `frames.txt`. Both files are re-derived and compared
by the checker, together with their SHA-256 digests in `evidence.json`.

## Implementation and comparison

No Rust implementation is proposed here and no reconstructed-source claim is
made; this is a static census of loader tables, so the comparison section is
"not yet measured" for source equivalence.

The checker re-derives every recorded value from the pinned bytes and compares
it field by field with `evidence.json`. It carries corruption controls: the
comparator must report a changed scalar, must stay silent on an identical
scalar, and must report a missing record; the line-digest helper must change
when a recorded line changes. The excerpt files are restricted to lines the
checker actually derived and must be in increasing slot order, so a hand-edited
or invented line is rejected.

## Results and limitations

Denominator: **169 constructor-table slots** (168 `.init_array` + 1
`.fini_array`), all bound through `R_X86_64_RELATIVE` relocations. This is a
static byte observation over the pinned digest.

Limits:

- The target binary was never executed; this says nothing about what any entry
  function does, its arguments, its effects or its ordering guarantees.
- No function body, call target, vtable, data layout or source name is
  recovered, and no reconstruction gate is claimed.
- The 168 recorded entry addresses are the relocation addends. Whether each is
  a distinct function, a shared helper or an alias is outside this packet.
- `.eh_frame` coverage means a slot address lies inside an authenticated FDE
  extent; it is not proof that the addressed function is complete or exclusive.
- Only `.rela.dyn` `R_X86_64_RELATIVE` records are used. Relocations of other
  types, `.init_array` sorting behaviour of the loader and any runtime patch of
  these tables are not analysed.
- Slots 12-163 are recorded in the packet data files, not individually in this
  README.

Next question: resolve which of the recorded constructor entry addresses are
reached from `.text` as ordinary code, beginning with the single `.fini_array`
entry `0x14193a0` and its containing FDE.
