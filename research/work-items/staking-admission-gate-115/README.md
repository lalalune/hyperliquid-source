# staking: recover node #115 signer admission gate, action class table, listed-signer search and known-user resolution

This packet makes it possible to write the signer admission step of node #115 from bytes: which of the 92 raw action words need a validator signer (1 word), a validator or listed signer (1 word, also every word below `0x86`), any signer (38), a known user (47) or are refused (5), which status each failure returns (`0x7f`, `0x5b`, `0x81`, success `0x1a2`), how the chain byte picks one of two lazily built listed-address sets, how the B-tree search over that set compares 20-byte keys and what its four-word result record holds, and the exact three-stage known-user lookup (user map, owner rows, second map) with its payload rules and the stack bytes the outlined copy forwards. The two gate copies, the outlined known-user stage, the class getter and the B-tree search run as real bytes in an interpreter inside the tool and agree with a separately written rule list on 15,928 constructed cases and 230 class-getter words with 0 mismatches; 216 of 216 negative controls are detected.

- Component ID: staking (Staking and validator lifecycle); first task: validator membership for signed actions. The packet requests no gate.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6` / the reference is not used for any claim here.
- Claim status: observation for everything under Evidence (ELF bytes, run by the interpreter of this tool); inference lines are marked; unresolved items are under limitations.
- Scope included (real bytes): the gate with an inline known-user stage `0x2bdb230`, the gate with the stage outlined `0x4d907c0` and its stage helper `0x55fedb0`, the class getter `0x36c2030` (reached through the slot `0x64e7860`), the listed-set B-tree search `0x149e4b0` (also called directly), the class table `0x79dd60` (92 bytes) and the three other-chain listed addresses at `0x464946`, `0x46495a`, `0x46496e`. Stubs with checked arguments: validator lookup (slot `0x64e4e38`, target `0x36c8430`), once call (slot `0x64df9f0`), memcmp (slot `0x64dfb50`), user map reader `0x4716b00`, hasher `0x4717440`, row finder `0x3ee6740`, second-map finder `0x3ee69c0`.
- Excluded and why: a third gate copy at `0x4d909b0` and the user map reader `0x4716b00` are named by the merged packet `RE-017-abci-item-prep-115` (route of the item preparation), so they are not claimed here: `0x4716b00` is a stub whose arguments are checked, `0x4d909b0` is not run. The callers are not read. A rel32 call scan made during the analysis (not a generated file) found the inline gate called from `0x2d3cc30` (2 sites) and the outlined gate from `0x4d90ee0` and `0x5921e20`. The #94 packet `staking-vote-quorum-94` was a lead for the question; no #94 address, constant or status number is reused (the #115 class table has 92 entries, the status numbers differ, and the user stage has a different shape).

## Reproduce

From the repository root, with Python 3 and the standard library only (no external program is started, the binary is never executed, the tool reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py` and checks the input SHA-256 first):

```
python3 tools/staking_admission_gate115.py --out research/work-items/staking-admission-gate-115
python3 -m unittest tests.test_staking_admission_gate115
```

The tool takes about 11 seconds with 4 worker processes and about 0.4 GB of memory. Generated files: `evidence.json`, `measure.json`, `path.tsv`, `class-table.tsv`, `class-sweep.tsv`, `function-rows.tsv`, `constants.tsv`, `listed.tsv`, `scenarios.tsv`, `mutations.tsv`, `controls.tsv`. `MANIFEST.sha256` covers them and this README. Two regenerations into different folders are byte equal.

## Evidence

All addresses are virtual addresses of the ELF; function bounds come from the FDEs; GOT slot targets come from `.rela.dyn` RELATIVE rows. `function-rows.tsv` holds the 522 reached instructions of the five real bodies with their bytes; `constants.tsv` holds every reached immediate; `path.tsv` gives the body size and the reached part of each function (inline gate 885 of 891, outlined gate 483 of 483, stage helper 525 of 532, getter 30 of 30, B-tree search 234 of 243).

### Class getter and table

`0x36c2030` loads the action word, subtracts `0x86`, takes index `0x14` when the subtraction borrows, and returns the byte at `0x79dd60 + index`. So any word below `0x86` is read as table entry 20, which is class 1. `class-table.tsv` has the 92 rows; counts are class 0: 1 (`0x9f`), class 1: 1 (`0x9a`, also every word below `0x86`), class 2: 38, class 3: 47, class 4: 5 (`0xbe`, `0xbf`, `0xc1`, `0xcc`, `0xcd`). `class-sweep.tsv` is the getter run on words 0..`0xe5`; the byte after the table is `0xe1`, which is not a class, so words from `0xe2` up are outside the claim.

### Gate

Both gates take (out, action, signer, exchange). The class picks a jump-table arm (`0x60a070` and `0x914e98`: classes 0 and 1 share arm 0, classes 2, 3, 4 have their own; in the inline gate the table's fifth and sixth words point past the function end).

| Class | Rule | Failure |
|---|---|---|
| 0 | validator lookup of the signer must succeed | `0x7f` |
| 1 | validator lookup, else the listed set of the chain | `0x7f` |
| 2 | any signer | none |
| 3 | known user | `0x5b` with the signer as payload |
| 4 | refused | `0x81` |

Success is status `0x1a2` with the 20-byte payload at `+2`. For classes 0, 1 and 2 the payload is the signer itself.

Listed set choice (class 1): exchange byte `+0xb9a` (the validator state is at `+0x3f08`) equal to 3 selects the lazy set behind slot `0x64dfff8`, any other value the one behind `0x64e0000`. Each set is a LazyLock: word `+0x28` nonzero means the once call (slot `0x64df9f0`, flag 1) runs first; then root `+0`, height `+8`; a root of 0 fails at once with `0x7f`. The search `0x149e4b0` walks nodes linearly (keys of 20 bytes at node `+8`, count at `+0xe6`, edges at `+0xe8`), compares with memcmp, and returns a record of four words: found flag (0 found, 1 not found), node, remaining height, edge index (the position of the first key not smaller than the probe, or the count). `scenarios.tsv` keeps the compare count per case. The other-chain addresses are 3 consecutive 20-byte rows in `.rodata` (`listed.tsv`).

Known-user stage of the inline gate `0x2bdb230`, in order: (1) user map `+0x3b80` through `0x4716b00`, found gives the stored 20-byte value as payload; (2) rows at `+0x7c8` (count `+0x7d0`, stride `0x510`): a row length of 0 is skipped, 1 compares the signer with the key at `[row+0x68]+0x80`, more hashes with `0x4717440` and asks the row table at `row+0x78`; a hit gives the signer as payload; (3) second map `+0x3f8..+0x430`: length 1 compares the key at `[+0x3f8]+0x58`, length 0 fails without reading any key, more hashes and asks the table at `+0x408`. A miss returns `0x5b` with the signer as payload. The outlined gate `0x4d907c0` calls `0x55fedb0` (signature out, exchange, signer), whose body is this same three-stage lookup with the same exchange offsets; the tool compares the helper's record with the inline gate's on every ninth user world in the tests.

The outlined gate copies the helper's whole `0x70`-byte record when the status is not `0x1a2`: after a miss the bytes `22..0x6f` of the out record are the untouched stack of the gate frame (the tool's stack fill byte `0xa5`; on a real run these bytes are indeterminate and must not be treated as data). After a hit only the status and the 20 payload bytes are written.

### Stub contracts

| Stub | Address | Arguments checked | Result given |
|---|---|---|---|
| validator lookup | slot `0x64e4e38` | state pointer `exchange+0x3f08`, 20 signer bytes | boolean in `al` from the fixture's validator set |
| once call | slot `0x64df9f0` | lock address `+0x28` names one of the two sets, flag 1 | installs the fixture set, clears the state word |
| memcmp | slot `0x64dfb50` | length 20 | -1, 0, 1 by byte order |
| user map reader | `0x4716b00` | map pointer `exchange+0x3b80`, 20 key bytes | pointer to the 20-byte value or 0 |
| hasher | `0x4717440` | the two hasher words of the owner (map, row or second map), 20 key bytes | token `0x5000 + sum(key)` |
| row finder | `0x3ee6740` | token equals the hash of the closure's key, row length in the closure | non-null when the fixture row holds the key |
| second-map finder | `0x3ee69c0` | table `exchange+0x408`, token, length in the closure | non-null when the fixture set holds the key |

A stub that sees a different argument raises a fixture error, so a case cannot pass with a wrong call shape.

### Method notes

- The interpreter decodes only the instruction forms that the five bodies use and raises on any other byte pattern, so a body cannot be run past a form it does not model.
- Every case builds its own exchange record in a heap of 0x80000 bytes filled with a poison byte; the stack is refilled per case, so uninitialised reads show up as the poison value.
- The lazy sets are installed in a 0x60-byte overlay at the two static addresses (`0x64efc80`, `0x64efcb0`), the only writable static state the gates read.
- Byte edits are applied to the code bytes the interpreter fetches; the file on disk is never changed.
- Case streams use their own xorshift generator and fixed seeds, so the case list is the same on every Python version.

### Dependencies not reconstructed

The validator lookup returns a boolean in `al`; the stubs check the state pointer, the 20 key bytes, the hash token passed to the finders and the length in the finder closure. The unwind pads and panic slots (`0x64df620`, `0x64df4c0`, `0x64df830`) are not reached by any case.

## Implementation and comparison

`tools/staking_admission_gate115.py` holds the x86-64 subset interpreter (decoder, flags, SSE2 compare forms) and the rule lists `spec_gate` and `spec_search`. The rule lists are written from the reading above, not from the interpreter, and predict: the full 0x80-byte out record (unwritten bytes keep a fill byte), the ordered stub log, the key compare count and, for the direct search, the result record and the node's length and first key. Case groups (`evidence.json`): `class_sweep` 13,680 (both gates, 95 words, validator yes/no, chain byte 3/2/0, 5 set shapes per chain, lock state ready/once), `tree` 120 and `tree_mixed` 64 (sets of 3..100 keys, first/middle/last/absent, one tall and one short set), `user_inline` 1,764 (both gates, 0..7 users, 4 positions, 7 row shapes, 6 second-map shapes), `btree_direct` 300 (11 set sizes from 1 to 100 keys, 3 key shapes, present and absent probes). No Rust reconstruction is written; the comparison is between the interpreter run of the original bytes and the independent rule lists.

Negative controls (all 216 detected, listed in `controls.tsv`): 92 single-byte class-table damages (the rule list reading a damaged table disagrees with the getter on its word), 15 deliberately wrong rule lists (wrong status values, wrong chain selection, dropped payload, dropped stub log entries, a wrong compare count, wrong niche, ...), 102 byte edits of reached instructions in the five real bodies (condition bits and immediates; `mutations.tsv`) where every edit changes the result on one of up to 24 picked cases that reach it, and 7 out-of-range inputs (wrong digest, non-FDE address, address outside the FDEs, address outside the file, a class word far outside the table, a tag past the rule list's table, a class byte past the jump table).

## Results and limitations

15,928 cases and 230 class words: 0 mismatches. Negative controls 216, detected 216; byte edits possible 102, killed 102, survived 0. The first full run of the rule lists against the bytes matched; the outlined helper and the direct search needed no model change.

- Not reconstructed: the validator lookup (838 bytes), the hash and table finders, the real `0x4716b00`, and the lazy set builder behind slot `0x64df9f0` (the once stub installs the fixture set). The chain-3 set contents are not read (the other-chain addresses are).
- The lock state field, the gate callers and the dispatcher above them are not read; what chooses the inline or the outlined copy is unknown.
- The two gate copies use the same exchange offsets here (`+0x3f08`, `+0xb9a`); their agreement is shown only through the same rule list over the same cases.
- Names of the 92 actions are not assigned; no gate is requested.

Next question: the validator lookup `0x36c8430` (what makes a signer a validator in #115) run as real bytes, and the callers of the gate copies.
