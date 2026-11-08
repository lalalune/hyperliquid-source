# staking: recover the node #115 reference authorization body (sixteen-way variant table, index map limits, signer test through the validator snapshot lookup, result record) in three copies

This packet makes it possible to write, from bytes, the function that decides whether a signer may act on the row a request names: it reads one of sixteen request variants through a jump table in `.rodata` (three variants pass with no test, eight take a row index from a fixed field offset, one maps a capped index through a table, one scans the rows for the signer), checks the index against the row count, asks the validator snapshot lookup `0x36c8430` (slot `0x64e4e38`) whether the signer is a member, and returns one of six result codes (`0x1a2`, `0xef`, `0xee`, `0xfa`, `0x154`, `0x66`) with exact side effects (one 8-byte box allocated and freed, the lookup's status drops, or a panic). The three bodies `0x2c58950`, `0x55cee20` and `0x55cf140` run as real bytes in an interpreter inside the tool, together with the real lookup chain (lookup, ring search `0x4551810`, B-tree step `0x37c5530`, status drop `0x36dae30`) and the allocation wrapper `0x2b7b820`, and agree with a separately written rule list on 12,690 constructed cases with 0 mismatches; 98 of 98 negative controls are detected.

- Component ID: staking (Staking and validator lifecycle), reached through the signer membership test of `staking-validator-snapshot-lookup-115`. The packet requests no gate.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30` / the reference is not used for any claim here.
- Claim status: observation for everything under Evidence (ELF bytes, run by the interpreter of this tool). Lines marked inference are not proved. Unresolved items are under limitations.
- Scope included (real bytes): the three bodies of 786 bytes each (one FDE each, 181 instructions each), the 16-entry jump table at `0x60aeac`, the lookup chain named above, the allocation wrapper `0x2b7b820`. Hooks (recording only): the allocator slot `0x64df480`, the allocation error slot `0x64df490`, the free slot `0x64df4a0`, the panic slots `0x64df620`, `0x64df830`, `0x64df4c0`.
- Excluded and why: the callers of the three bodies (those that build the request and read the 0x20-byte result record), the larger sibling `0x2c58320` (1,362 bytes, it continues into `0x2bfd360` after the same test), the 602-byte sibling `0x2c54de0` that forwards the membership bit to a slot, the snapshot store writers, and the meaning of the row fields other than the flag byte and the 20-byte address. No #94 address is used.

## Reproduce

From the repository root, with Python 3 and the standard library only (no external program is started, the binary is never executed, the tool reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py` and checks the input SHA-256 first):

```
python3 tools/staking_validator_reference115.py --out research/work-items/staking-validator-reference-115
python3 -m unittest tests.test_staking_validator_reference115
```

Generated files: `dispatch.tsv`, `bodies.tsv`, `groups.tsv`, `scenarios.tsv`, `controls.tsv`, `result.json`, `measure.json`. `MANIFEST.sha256` covers them and the README. The tool starts four forked workers, runs in about 25 seconds and peaks below 300 MB of resident memory per process. Cases are built one at a time, run, compared and counted; no per-case result list is kept.

## Evidence

All addresses are virtual addresses of the ELF; function bounds come from the FDEs; slot targets come from `.rela.dyn` RELATIVE rows; `dispatch.tsv` lists the sixteen table rows exactly as the tool reads them (`target = 0x60aeac + signed dword`).

### Entry (rdi = result record, rsi = state, rdx = pointer to the 20-byte signer, rcx = request)

1. The first request word `w` selects the variant: a value with bit 63 set gives `w xor 2^63` (0..15), any other value gives variant 8 (the one data-carrying variant). The jump table has no range check, so only 0..15 are modelled.
2. Variants 0, 1, 4 jump straight to the exit that stores `0x1a2` (no test at all). Variants 3, 7, 9 read the row index from request `+0x20`, variant 2 from `+0x50`, variant 8 from `+0x60`, variants 6 and 11 to 15 from `+0x08`. Variant 5 reads `+0x48` and maps it (below). Variant 10 scans.
3. Index variants: allocate an 8-byte box through `0x64df480` (a null return calls the allocation error slot `0x64df490` with 8, 8), compare the index with the row count `[state+0xb8]`; at or past it the body frees the box and stores `0xfa`. Otherwise the index is stored in the box.
4. The snapshot test: `0x36c8430(state+0x3f08, signer)` (the copy at `0x55cee20` uses `state+0x4a78`, the other two use `state+0x3f08`). A true result, or a signer that is all 20 zero bytes, clears the bit `flag`; any other signer that is not a member sets it. The test is made with `pcmpeqb`/`pand`/`pmovmskb` over 16 plus 4 bytes.
5. The row is `[state+0xb0] + index*0x158`. If its byte at `+0x142` is not 1 the result is `0x1a2` when `flag` is clear and `0xef` when it is set. If the byte is 1 the result is `0x1a2` only when `flag` is set and the 20 bytes at `+0x143` equal the signer, else `0xef`. The box is freed with (size 8, flags 0) before the code is stored.
6. Variant 5: the value `v` at request `+0x48`: `v >= 0x0ccccccccccccccc` stores `0x154` with `v` at record `+8`; `v > 0x270f` or `v >= [state+0xa0]` stores `0x66` with `v` at `+8`; otherwise the box is allocated through the wrapper `0x2b7b820`, the index becomes the u64 at `[state+0x98] + v*0x20`, and the flow joins step 4 **without** the row-count test of step 3. A mapped index at or past the row count therefore reaches the bounds test after the lookup and calls the panic slot `0x64df830` (location `0x64768d8`); the box is not freed on that path. A mapped index past the row count is observable in 36 cases per body.
7. Variant 10: for each row in order, a row whose byte at `+0x142` is 1 and whose 20 bytes at `+0x143` equal the signer ends the scan with `0x1a2`. No match (or no rows) stores `0xee` with the static string pointer at record `+8` and length `0x26` at `+0x10`. The scan does not call the lookup and does not allocate. The signer is not tested for zero, so a zero signer matches a flagged zero row. The string is `deployer has not deployed a spot token` (read from `.rodata`; `0x60e77e` in the first body, `0x92a398` in both copies).
8. The result record is a u16 code at `+0`; only the codes `0xee`, `0x154`, `0x66` write the words at `+8` and `+0x10`. Every other byte of the 0x20-byte record keeps its prior value (checked on every run). The state, the request and the signer are never written (checked on every run).

### Copies

`0x55cee20` differs from `0x2c58950` in one displacement (`state+0x4a78` instead of `state+0x3f08`) and in the position of the allocation error tail and the string pointer; `0x55cf140` differs only in the tail layout and the string pointer. Every case runs in all three bodies, and the fixture holds a different (decoy) store at the other copy's offset, so a body that reads the wrong offset disagrees with the rule list.

### Coverage

`bodies.tsv` lists the unreached instructions: 17 per body, i.e. 164 of 181 reached. They are the fall-through of a no-return panic call (`0x2c58a44`), alignment padding (`0x2c58b15`), two panic arms that the tests before them exclude (a zero row count inside the scan loop, and the map bounds check after `v < [state+0xa0]`; `0x2c58c24` to `0x2c58c3b`, `ud2`) and the unwinding cleanup (`0x2c58c43` onward), which needs an unwinding panic. The allocation error branch itself is reached by the allocation failure cases.

## Implementation and comparison

The tool `tools/staking_validator_reference115.py` is the implementation: a concrete x86-64 interpreter (the engine of `tools/staking_validator_snapshot115.py` up to the `Lookup` fixture class, with its decoder and 16-byte vector subset; it raises on any form that is not in these bytes), a `Ref` fixture that builds the state (rows, index map, two stores, request record, signer), and a rule list `spec` written without the machine. A case is one (body, request variant, situation, snapshot world) tuple:

- 36 snapshot worlds (ring and B-tree outer stores, vector and B-tree inner snapshots, 0 to 3 snapshots, probes: member first/last/middle, other epoch's member, absent, near miss in the last byte), each used as real store and as decoy store of another case.
- Per index variant 9 row situations (match, near miss at byte 0/5/15/16/19, inactive row 0, flag 2, index equal to the row count, empty table, 2^63 or 2^64-1, zero signer with a matching row, zero signer with an inactive row), per mapped variant 10 situations (hit, mismatch, mapped past the rows, index equal to the map length, `0x2710` and `0x270f` with a 10,001-entry map, `0x0ccccccccccccccc` and one below, index 0, a longer table), per scan variant 8 situations (first, second, inactive then active, flag 2 only, none, empty, near miss, zero), allocation failure on the match (or hit) situation of every 23rd world.
- The expected outcome is the full result record (32 bytes), the allocation/free/drop log and any panic or allocation-error tuple. 12,690 cases, 3,337,551 interpreted steps.

Negative controls (98, all detected):

- 18 deliberately wrong rule lists (inverted membership, zero signer counted as non-member, scan ignoring the flag, scan accepting flag 2, nonzero row flag accepted, address compared on 16 bytes only, limits `0x0ccc...cd` and `0x2710`, missing map length test, mapped index checked early, missing free, no free on the range path, untested variants checked, offset `0x20` read at `0x50`, inactive rows denied, swapped codes, message length 0x27, decoy store read).
- 66 byte edits (22 per body: condition flips of conditional jumps/moves and immediate flips, chosen round robin over both kinds); 66 killed, 0 survived.
- 8 dispatch-table damages (variants 2, 5, 8 and 10 each given the arm of variant 3 or of variant 0 in the rule list); all 8 detected. Two of them (variants 2 and 8 taking the arm of variant 3) differ from the bytes only in the field offset read, which the rule list models by reading the assumed field of the request.
- 6 range controls: wrong input hash, address inside an instruction as an FDE start, jump table entry outside the arms, a 12-step limit, an entry in the middle of an instruction, the store read at the other body's offset.

## Results and limitations

- `measure.json`: `cases` 12,690, `negative_controls` 98, `negative_detected` 98, 66 edits tried/killed/0 survived, 36 worlds. `groups.tsv` has the outcome counts per body and arm (for example index arm per body: `0x1a2` 869, `0xef` 1,485, `0xfa` 1,188, allocation error 22; mapped arm: `0x1a2` 43, `0xef` 135, `0x66` 108, `0x154` 36, panic 36, allocation error 2; scan: `0x1a2` 144, `0xee` 144; untested variants: `0x1a2` 18).
- Observation limits: the fixtures are built by this tool (B-trees and rings in the layouts of the snapshot packet), not captured from a node. The row layout uses only the flag byte `+0x142` and the 20-byte address `+0x143`; other row bytes are filler. Variants above 15 are not modelled (the table has no bound). The unwinding cleanup is not run.
- Inference (not proved): the static string at the scan failure suggests that the rows are spot-token deploy rows, the address the deployer and the variants spot-deploy request kinds, which would make this body part of an exchange path, not of staking; it is filed under staking only because the membership test it calls is the staking snapshot lookup. The request bit `flag` (non-member, non-zero signer must equal the row address) suggests that a snapshot member may act on any row while others must be the row's own deployer. Neither claim is used by the tool.
- No gate is requested. This is one authorization body and its copies, not the component.

Next question: who builds the 0x20-byte request and reads the result record (callers of the three bodies), and what the sibling `0x2c58320` does after the same test when it calls `0x2bfd360`.
