# staking: recover the node #115 validator-gated nested-key check (row gate, 20-byte key set walk, row-index map, record builder arguments) in three copies

This packet makes it possible to write, from bytes, the function that decides whether a signer may act on a numbered row and then asks a record builder to act on a 20-byte key of that row: it asks the validator snapshot lookup `0x36c8430` (slot `0x64e4e38`) whether the signer is a member (an all-zero signer counts as a member), applies one of two row-flag rules (`0xef` on failure), walks a B-tree set of 20-byte keys hanging off the row (`0x170` when the key is not in it), derives a 20-byte index key from the row number (big-endian, or twenty `0x22` bytes when a state sentinel names this row), reads a per-key map of row numbers to values (a ring or a B-tree), and calls the 12.5 KB record builder `0x2bfd360` with an exactly known argument block. The three bodies `0x2c58320`, `0x55ce1c0` and `0x55ce720` (1,362 bytes each) run as real bytes in an interpreter inside the tool, together with the real lookup chain and the real nested ring search `0x45584b0`, and agree with a separately written rule list on 18,576 constructed cases with 0 mismatches; every one of the 289 instructions of each body is reached; 122 of 122 negative controls are detected.

- Component ID: staking (Staking and validator lifecycle), reached through the signer membership test of `staking-validator-snapshot-lookup-115`. The packet requests no gate.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30` / the reference is not used for any claim here.
- Claim status: observation for everything under Evidence (ELF bytes, run by the interpreter of this tool). Lines marked inference are not proved. Unresolved items are under limitations.
- Scope included (real bytes): the three bodies of 1,362 bytes (one FDE each, 289 instructions each), the lookup chain `0x36c8430` / `0x4551810` / `0x37c5530` / `0x36dae30`, the nested ring search `0x45584b0`, the 20-byte-key B-tree walk and the u64-key B-tree walk inside the bodies. Hooks (recording or modelled): the hash-map get `0x4716cc0` (a host map from 20-byte key to a ring or B-tree header), the record builder (`0x2bfd360`, `0x54e9610`, `0x54e6510`; the tool records its arguments and returns a chosen 0x70-byte result), the memcmp slot `0x64dfb50`, the free slot `0x64df4a0`, the lazy-cell slot `0x64df9f0`, the panic slots `0x64df620`, `0x64df830`.
- Excluded and why: the record builder itself (12,538 bytes, a later packet), the real SipHash and probe of the map get (205 bytes plus the hasher; the host map stands in), the callers of the three bodies, the other caller families of slot `0x64e4e38`, and the meaning of the row fields other than the flag byte, the 20-byte address, the tag, root and height words. No #94 address is used.

## Reproduce

From the repository root, with Python 3 and the standard library only (no external program is started, the binary is never executed, the tool reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py` and checks the input SHA-256 first):

```
python3 tools/staking_validator_nested_key115.py --out research/work-items/staking-validator-nested-key-115
python3 -m unittest tests.test_staking_validator_nested_key115
```

Generated files: `targets.tsv`, `bodies.tsv`, `groups.tsv`, `scenarios.tsv`, `controls.tsv`, `result.json`, `measure.json`. `MANIFEST.sha256` covers them and the README. The tool starts four forked workers, runs in about 30 seconds and peaks below 420 MB of resident memory per process. Cases are built one at a time, run, compared and counted; no per-case result list is kept.

## Evidence

All addresses are virtual addresses of the ELF; function bounds come from the FDEs; slot targets come from `.rela.dyn` RELATIVE rows. `targets.tsv` lists, per body, the three direct call targets and the panic message location exactly as the tool reads them from the instruction bytes.

### Entry (rdi = result record of 0x70 bytes, rsi = state, rdx = pointer to the 20-byte signer, rcx = pointer to a 20-byte key, r8 = row index)

1. Membership: `0x36c8430(state+0x3f08, signer)` (the copy `0x55ce720` uses `state+0x4a78`, the other two use `state+0x3f08`). A true result, or a signer whose 20 bytes are all zero (tested with `pcmpeqb`/`pand`/`pmovmskb` over 16 plus 4 bytes), selects the member rule; any other signer selects the non-member rule.
2. Row: `[state+0xb0] + index*0x158`, row count `[state+0xb8]`. An index at or past the count calls the panic slot `0x64df830` (message location `0x64768d8` in all three bodies) after the lookup has run, so the lookup's status drops are already logged. The flag byte is at row `+0x142`, the 20-byte address at `+0x143`.
3. Member rule: flag byte 0, else the result is `0xef` (a 2-byte code, the other 0x6e bytes of the record keep their prior value). Non-member rule: flag byte 1 and the 20 address bytes equal the signer, else `0xef`.
4. Key set: the row dword at `+0x10` must be 1 and the pointer at `+0x18` non-null, else `0x170`. The pointer is the root of a B-tree of 20-byte keys whose height is the qword at `+0x20`: keys at node `+8` (stride 20), `u16` length at `+0xe6`, edges at `+0xe8`. A search compares the key with every key of the node through the memcmp slot `0x64dfb50` (length 0x14) and descends by the count of smaller keys; a hit ends the search, a miss at height 0 gives `0x170`. The value of the set is never read.
5. Index key: when the dword at `state+0x80` is 1 and the qword at `state+0x88` equals the row index, the 20 bytes are `0x22` and the tag byte is `0x22`; otherwise the 20 bytes are the row index as a big-endian u64 followed by 12 zero bytes and the tag byte is `0x20`.
6. Per-key map: `0x4716cc0(state+0x3f0, key)` returns a header pointer or null (null selects a static empty header at `0x64fd958`, four zero words). The cell at `0x64fd9a8` is read after the get; a non-zero cell calls the slot `0x64df9f0` with (cell, 1, ...) and then continues. The header is a ring (capacity, buffer, head, length) of 32-byte elements `[u64 row number; 24 value bytes]` searched by `0x45584b0`, or, when its first word is `2^63`, a B-tree (root, height, length) with u64 keys at node `+8`, values (stride 24) at `+0x60`, `u16` length at `+0x16a` and edges at `+0x170`. The value used is the first qword of the value of the entry whose key equals the row index, or 0 when there is none (an empty tree or an all-smaller key also give 0).
7. Builder call: `0x2bfd360(result, state, args)` with an argument block whose defined bytes are: qword 0 at `+0`, 3 at `+0x10`, the row index at `+0x20`, the map value at `+0x28`, 0 at `+0x30`, the 20-byte key at `+0x88`, the tag byte at `+0x9c`, index-key bytes `[8..16)` at `+0x9d`, `[15..19)` at `+0xa4`, `[0..8)` at `+0xa8`, a 1 byte at `+0xb0` and the signer's 20 bytes at `+0xb1`. The copies call `0x54e9610` and `0x54e6510` with the same block.
8. Result: when the builder's code (u16 at result `+0`) is `0x1a2`, a non-zero size qword at result `+8` is released through the free slot `0x64df4a0` with (pointer at `+0x10`, size, 0) and the caller's record gets the code only; for any other code the whole 0x70-byte result is copied to the caller's record. The state, the signer and the key are never written (checked on every run).

### Copies

`0x55ce1c0` differs from `0x2c58320` only in rel32 displacements (it calls the same hash-map get and ring search, a different builder `0x54e9610`). `0x55ce720` additionally reads the store at `state+0x4a78`. Every case runs in all three bodies, and the fixture holds a different (decoy) store at the other copy's offset, so a body that reads the wrong offset disagrees with the rule list.

### Coverage

`bodies.tsv`: 289 of 289 instructions reached in each body, including the rare arms (an all-smaller key in the u64 B-tree leaf, an empty u64 B-tree, the lazy-cell call, the three result paths).

## Implementation and comparison

The tool `tools/staking_validator_nested_key115.py` is the implementation: a concrete x86-64 interpreter (the engine of `tools/staking_validator_snapshot115.py` up to its `Lookup` fixture class, with its decoder and 16-byte vector subset; it raises on any form that is not in these bytes), a `Gate` fixture that builds the state (rows with their key-set B-trees, two stores, the host map with ring and B-tree headers, the sentinel words, the lazy cell), and a rule list `spec` written without the machine. A case is one (body, situation, snapshot world) tuple:

- 36 snapshot worlds (ring and B-tree outer stores, vector and B-tree inner snapshots, 0 to 3 snapshots, probes: member first/last/middle, other epoch's member, absent, near miss in the last byte), each used as real store and as decoy store of another case.
- Per body and world: 27 gate situations (signer: the world's probe, an outsider, the zero signer; row flag 0/1/2; row address equal / one byte different / other), 5 row-index situations (equal to the count, huge, 2^63), and 140 deep situations that pass the gate and vary the key set (tag 0/5/2^20 over a real tree, tag 1 with no keys, 7 set sizes 1..144 with the key first/middle/last, 3 sizes with the key below, above, between or one byte off), the sentinel (4 combinations of the dword and the qword), the map (absent key, ring hit, ring miss, B-tree hit, B-tree miss, key of another entry, B-tree with only smaller keys, empty B-tree), the builder result (code `0x1a2` with and without a block to free, two other codes), and the lazy cell.
- The expected outcome is the full 0x70-byte result record, the hook log (drops, map get key, lazy call, builder arguments, free) and any panic tuple. 18,576 cases, 9,715,515 interpreted steps.

Negative controls (122, all detected):

- 24 deliberately wrong rule lists (inverted membership, zero signer counted as non-member, member rule accepting flag 1, non-member rule ignoring the flag, address on 16 bytes only, tag ignored, empty set found, key on 16 bytes only, key always found, sentinel index or flag ignored, little-endian index, swapped tag byte, absent value 1, second value word, lazy cell ignored, missing free, free on a zero size, payload kept on the OK path, decoy store read, swapped `0xef`/`0x170` codes, signer used as key, row 0 always).
- 90 byte edits (30 per body: condition flips of conditional jumps/moves/sets and immediate flips, chosen round robin over both kinds); 90 killed, 0 survived.
- 8 range controls: wrong input hash, address inside an instruction as an FDE start, a 12-step limit, an entry in the middle of an instruction, the store read at the other body's offset, hook targets taken from another body, the panic-site search on a non-body address, the call scan on a body of another family.

## Results and limitations

- `measure.json`: `cases` 18,576, `negative_controls` 122, `negative_detected` 122, 90 edits tried/killed/0 survived, 36 worlds. `groups.tsv` has the outcome counts per body and family (per body: gate `0xef` 774 and builder reached 198, bounds panic 180, deep `0x170` 2,296 and builder reached 2,744).
- Observation limits: the fixtures are built by this tool (B-trees and rings in the layouts of the snapshot packet and of the node layouts above), not captured from a node. The hash-map get `0x4716cc0` is a host map: its SipHash and probe are not run, so the claim is "the body passes this key and reads this header", not "the map is laid out like this". The record builder is not interpreted; only its arguments are checked. Row bytes other than the flag, address, tag, root and height are filler. The lazy-cell state meaning (which value is "initialised") is not established.
- Inference (not proved): the earlier packet `staking-validator-reference-115` found the same row layout (flag `+0x142`, address `+0x143`) with a message about spot-token deploys; the 20-byte keys here suggest an address-keyed set per row and the map suggests per-address row-number values, but neither interpretation is used by the tool. The sentinel suggests a special "current" row whose index key is a constant. No gate is requested.

Next question: the record builder `0x2bfd360` (12.5 KB) and its two copies, and the real SipHash probe of `0x4716cc0`, which would make the map get real bytes instead of a host map.
