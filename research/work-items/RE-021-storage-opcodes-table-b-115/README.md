# RE-021: reconstruct the SLOAD, SSTORE, TLOAD and TSTORE handlers of node #115's second and third opcode tables, with the journaled store 0x4326080

This packet lets you rebuild, as runnable Python, how node #115 executes the four storage opcodes through the handler tables
at `0x6485ef8` / `0x6486c60` (family B) and `0x649eea0` (family C). `sload()` replaces the stack top by the slot value and, from
spec 7 on, hands the load a skip flag (`gas < params +0xc8`) and charges `params +0xc8` for a cold slot. `sstore()` is the
sstore-gas arithmetic in front of the journaled store `0x4326080`, which looks the account up, marks it touched with a
journal entry (tag 2), loads the slot, compares and, on a change, writes it and journals the old word (tag 8). `tload()` and
`tstore()` need spec 11. The model matches the real machine code in 12,000 of 12,000 cases, and 58 of 58 negative controls
are detected.

- Component ID: `evm` (task RE-021, address-09 transaction path; connected to RE-011)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main `0781ce048`. `references/can1357-hl` was not used. No node #94 result is reused.
- Claim status: observation (byte-level equality of the reconstruction with the evaluated machine code on every listed case,
  table slots read from `.rela.dyn`) plus inference. Names such as "SLOAD", "touched flag", "cold" and "skip flag" are inferred
  roles matched against the EVM instruction shape. They are not recovered symbols.
- Scope included and excluded:
  - Included, all executed as real code: SLOAD `0x4330ea0` and its family C copy `0x4f04140`; SSTORE `0x4331150` with its
    price body `0x433cac0` and refund body `0x433c830`; the journaled store `0x4326080`; the family C SSTORE `0x4f04400` (price
    and refund inlined) with its store `0x4f00c30`; TLOAD `0x43310d0` and `0x4f04370`; TSTORE `0x4331640` and `0x4f04dd0`. The
    opcode-table slots that point to them are read from the relocations.
  - Excluded, stubbed with argument recording: the account map lookups `0x3ed7e80` and `0x4ef9240` (hash map with a runtime
    secret, 0 of 70 instructions executed here), the fallible slot load `0x433bcf0` behind GOT `0x64e6d98` (owned by the merged
    RE-011 storage-cache-load packet), the journal Vec grow behind GOT `0x64e68e8`, the transient-storage helpers `0x43156c0`,
    `0x4324490`, `0x545e800`, `0x5464420`, and the overflow panic entries behind GOT `0x64df520` / `0x64df848`.
  - Not covered: the first family (`0x2994990`, `0x2977910`) belongs to the earlier packets and is not touched. No Rust
    implementation, and no gate is requested.

## Reproduce

From the repository root with Python 3 (standard library only, no binutils, nothing is executed):

```
python3 tools/re21_storage_opcodes_b115.py --out research/work-items/RE-021-storage-opcodes-table-b-115
python3 -m unittest tests.test_re21_storage_opcodes_b115
```

The tool checks the input SHA-256 first and fails on any other digest. It reads sections with `tools/elf_index.py` and FDE
extents with `tools/fde_extents.py`, applies `.rela.dyn` RELATIVE addends to the GOT and opcode-table words it follows, and
runs the real code bytes on an in-file concrete x86-64 evaluator whose decoder raises on unknown forms. The evaluator is the
one from the storage-cache-load packet, extended with OF for add/sub and with `sar`. Cases are made one at a time, run, compared
and dropped (the evidence file is written line by line). Two runs with different `PYTHONHASHSEED`/`TZ` and a binutils-free
`PATH` produced byte-identical output. A full run takes about 25 seconds. `MANIFEST.sha256` lists the hashes of every output.

## Evidence

Coordinates are virtual addresses in node #115; `.text` VA equals the file offset plus the section delta read from the section
header. Every row of `constants.json` is re-read from the ELF bytes on every run.

- Opcode tables (`constants.json` → `opcode_table_slots`): the SLOAD slot (opcode 0x54) minus `0x54*8` gives the table base.
  Family B has two tables, `0x6485ef8` and `0x6486c60` (same handlers in both); family C has `0x649eea0`. In all three the slots
  for opcodes 0x54, 0x55, 0x5c and 0x5d hold SLOAD, SSTORE, TLOAD and TSTORE. Family B points to `0x4330ea0`, `0x4331150`,
  `0x43310d0`, `0x4331640`. Family C points to `0x4f04140`, `0x4f04400`, `0x4f04370`, `0x4f04dd0`. The family C SSTORE has the price and refund
  arithmetic inlined and behaves like the family B chain on all 4,500 SSTORE cases (half per family).
- FDE extents and direct calls (`functions`): SLOAD 552 bytes / 129 instructions (calls the lookup only), SSTORE 1,263 / 287
  (calls `0x4326080`, `0x433cac0`, `0x433c830`), the store 726 / 152, TLOAD 126 / 36, TSTORE 150 / 39, the family C copies 552 / 129,
  143 / 39 and 142 / 39, the family C SSTORE 2,505 / 603 and its store 726 / 157. The price body is 336 / 105 and the refund body 653 / 187.
- Pinned bytes (`checked_bytes`): 14 code patterns re-read on every run, for example the spec threshold `cmpb $0x6,0x1a9(%rdi)`
  in SLOAD, the cold price load `params +0xc8`, the result bytes 0x2c / 0x20 / 0x36 / 0x2b / 0x28 / 0x25 and the reserve flag
  byte `+0x265`.
- Executed coverage (`summary.json` → `covered_instructions`): store 152/152 and 157/157 (copy), SLOAD 129/129 (both copies),
  SSTORE 287/287 and 595/603 (family C, eight instructions unreachable with the generated inputs),
  price 105/105, refund 181/187 (six refund instructions are unreachable with the generated inputs), TLOAD 36/36 and 39/39,
  TSTORE 39/39 (both copies). `decoded-instructions.tsv` lists every instruction with its bytes and an executed bit.
- `cases.tsv` keeps every fourth case plus any mismatch (3,000 rows); `outcome-classes.tsv` counts all 12,000 cases by outcome.

Observations from the bytes:

1. SLOAD: an empty stack returns 0x2c. With spec byte `+0x1a9` <= 6 the load gets skip flag 0 and any failure (missing account
   or load tag 2) returns 0x36. With spec > 6 the flag is `gas < params +0xc8`, a failure returns 0x20, and a cold result
   (tag bit 0) is charged `params +0xc8` before the stack top is written; a charge larger than the gas returns 0x20 without
   writing. The new top is the second 32-byte word of the load result record.
2. SSTORE: the first-family arithmetic (static gate 0x28, depth gate 0x2c, sentry 0x25 from spec 6, static charge `+0x98`, skip flag,
   price, reserve accounting behind host byte `+0x265`, signed refund counter with overflow panic) is repeated in the copies
   `0x433cac0` and `0x433c830`. What differs is the store: `0x4326080` always writes first byte 0 when it fails, so with spec > 6
   the failure result is 0x20 (the handler returns 0x36 only if that byte has bit 0 set), and 0x36 appears only for spec <= 6.
3. The store touches the account before the slot load: flag byte `+0x8c` bit 0x04 set, journal entry tag 2 with the 20-byte
   address, even when the load then fails. A changed slot is journaled with tag 8: address at +1, three stale key bytes at +0x15,
   the key at +0x18, the old word at +0x38 (stride 0x58). A Vec at host `+0x288` grows when len == cap.
4. TLOAD B reads the transient helper at host `+0x360`; TLOAD C reads it at host `+0x270`. Both TSTORE copies write through host `+0x270`.

## Implementation and comparison

`tools/re21_storage_opcodes_b115.py` holds one pure-Python reconstruction: `sstore_cost`, `sstore_refund`, `store_model`, `sstore_model`,
`sload_model`, `tload_model`, `tstore_model` and a `model()` that returns the result byte plus the expected bytes of every
region (interpreter, host, parameter table, stack, journal buffer, account record, slot record, result block). A case builds
the initial regions, the model mutates a copy, the evaluator mutates the real regions, and the comparison covers the result
byte, the call events (lookup, load with skip flag, grow, transient helper arguments), the callee-saved registers and all
regions byte for byte.

Cases (12,000, deterministic SHA-512 stream): 3,000 SLOAD (1,500 per copy), 4,500 SSTORE with the real store and cost chain (half per family),
1,500 direct stores (half per family), 1,500 TLOAD and 1,500 TSTORE (half per copy). Inputs include missing accounts, touched and untouched
accounts, load tags 0/1/2, journal Vec at len == cap, boundary prices (`2^64-1`, `2^63`), saturating reserve counters and
refund overflows.

Negative controls (58): 19 model mutants (swapped pop order, sentry threshold, store error code, cold price dropped, wrong
set/reset price, negate dropped, restore dropped, reserve gas dropped, release dropped, store always writing, SLOAD spec
threshold, TLOAD spec threshold, TSTORE static gate, no touch entry, journaling the new word, no cold charge and others), 37 code
mutants (one immediate or displacement byte changed in the handlers, the stores, the price and the refund, including the family C copies) and 2 input controls
(a flipped `.text` byte, an address past `.text`). A mutant that leaves a byte unchanged is refused by the tool.

## Results and limitations

- 12,000 cases, 0 mismatches; 58 of 58 controls detected (`measure.json`). The unit tests (13) check a sample, full coverage of
  the executed functions, every mutant, the digest and range refusals, the opcode-table slots, the pinned bytes, the journal
  layout and the cost/refund arithmetic on known values.
- The lookups `0x3ed7e80` / `0x4ef9240` return a synthetic record pointer; their hash is not modelled. The load behind GOT
  `0x64e6d98` is replaced by a fixed record and a tag. The account record flag `+0x8c` is the only account field the store uses.
- The names of the inferred roles are not symbols. No gate is requested.
- Next question: the account lookups `0x3ed7e80` / `0x4ef9240` with the runtime hash secret, then the transient-storage helpers
  `0x43156c0` / `0x4324490` (host `+0x360` and `+0x270` are different structures).
