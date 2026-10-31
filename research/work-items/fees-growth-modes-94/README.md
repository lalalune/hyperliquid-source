# fees: node #94 growth mode setter, the byte that turns on the 0.1 fee factor

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for byte-derived rules below, inference where marked, unresolved items listed under Results and limitations
- Scope included and excluded: included are the setter of asset byte +0x29 in all 3 copies, the name split, dex search and asset search it calls, and a byte pin of the fee reader. Excluded are the action arm and authority checks before the setter, the fee arithmetic in 0x37130b0, any writer of byte 2, and the map iterator and dex set, which are stubs.

## Reproduce

Run from the repository root:

```
python3 tools/fees_growth_modes.py --out research/work-items/fees-growth-modes-94
cd research/work-items/fees-growth-modes-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_growth_modes
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`. A full run takes about 400 s on 3 workers. Two full runs gave identical generated files.

## Evidence

Coordinates are virtual addresses in the ELF above. The objdump lines below are a reading aid from a human session. They are not part of the generated files, which come from bytes alone.

### Boundaries

- 0x273b4b0: FDE 0x10ef944, end 0x273bd91, 489 instructions decoded, 421 executed. Setter, copy A, called at 0x273fd15 in 0x273e080.
- 0x3332080: FDE 0xdf6530, end 0x333226b, 125 instructions decoded, 116 executed. Split at the first colon (slot 0x5773ec8).
- 0x3332270: FDE 0x116b42c, end 0x3332371, 67 instructions decoded, 59 executed. Dex search (slot 0x5774708, reached by a call from the split).
- 0x374a1a0: FDE 0xe4e77c, end 0x374a2bc, 79 instructions decoded, 72 executed. Asset number search (slot 0x5773318).
- 0x4d4b020: FDE 0x12e3274, end 0x4d4b901, 489 instructions decoded, 421 executed. Copy B, called at 0x4d51e51 in 0x4d50130.
- 0x4d4b910: FDE 0x12e32c8, end 0x4d4c1f1, 489 instructions decoded, 421 executed. Copy C, called at 0x4d57871 in 0x4d55b50.
- 0x1459ca0 time add and chrono helpers 0x15206e0, 0x151f870: run, not mutated; `fees-fee-scale-94` (open) mutates the first.

The instructions not run are listed with a reason in `evidence.json` under `unexecuted`. They are unwind tails, the code after a call that does not return, the list grow call, a product already checked by the asset search, and the clone failure path.

`evidence.json` compares the copies by decoded instruction with code addresses taken out. 0x4d4b020 has no differing row. 0x4d4b910 has 4: exchange +0x1038 for +0x5b8, +0x1372 for +0x8f2, +0x1040 for +0x5c0 and +0x1048 for +0x5c8. Each copy has one direct caller, listed there, and no relocated slot holds any of them. The copies call their own copies of the iterator, dex set and drop helpers, at the same offsets in the body.

### Input

Registers: rdi result, rsi exchange, rdx a map of 3 words (root, height, length). Each key is a String at node +8 + 24 x i and each value a byte at node +0x114 + i, which is the layout of an 11-key B-tree leaf. The setter owns the map and frees every key.

### First pass: test every key, write nothing

```
273b655: cmp     r14,0x64
273b65e: ja      273baaf                      ; tag 0x143
273b6d6: cmp     r14,[r13+0x30]               ; asset / 10000 == dex number
273b703: movzx   edx,byte [rax+rcx+0x29]
273b708: cmp     dl,1
273b70b: ja      273b872                      ; tag 0xe7
273b711: mov     r12d,ebx
273b714: xor     r12b,1                       ; new byte = value ^ 1
273b718: cmp     dl,r12b
273b71b: je      273b787                      ; same byte: no wait test
273b720: mov     ecx,[rax+0x1c]
273b723: test    ecx,ecx
273b725: je      273b787                      ; no last change
273b7a1: ucomisd xmm0,[20a730]                ; dex scale against 1.0
273b7a9: ja      273bc49                      ; tag 0xe6
273b868: cmp     byte [rcx+0x29],2            ; every asset of the dex
```

Rules, in order, for each key, checked against the model on every vector:

1. Name longer than 100 bytes: tag 0x143.
2. Dex: text before the first `:`. No colon, or a colon at offset 0, gives the empty dex name, which takes row 0 with no status test and panics by `unwrap` on an empty table. Otherwise the first row with byte +0x230 != 3 and that name, else tag 0x141.
3. Asset: the whole name, dex prefix included, against the asset rows, stride 0x30, else tag 0x64 with a clone of the name. The number is dex number x 10000 + i, and both steps panic on overflow at `l1/src/asset/pdi.rs:30:14`.
4. `number / 10000` must equal row +0x30 and the rest must be below the row count, else a panic at `l1/src/perp_meta.rs:194:38`. A row of over 10000 assets reaches it.
5. Asset byte above 1: tag 0xe7. This comes before every other test of the value, so a blocked asset refuses both true and false.
6. New byte = value ^ 1. True stores 0, false stores 1.
7. Only if the byte would change and the first dword at asset +0x1c is non-zero: last + wait, where wait is 2592000 s when the exchange mode byte is 3 and 60 s otherwise, from the table at 0x208d90. Past now gives tag 0xe0; equal passes. The compare is signed date word, then seconds, then fraction. The add panics past the chrono date range.
8. Only for true: if row byte +0x230 != 3 and dex scale (meta +0x60) is above 1.0, tag 0xe6. NaN passes. A true that keeps the same byte is still tested here.
9. Only for true, and once per dex: any asset of the dex with a byte of 2 or more gives tag 0xe7. A false key does not scan.
10. The pair (asset number, new byte) goes on a list of 16-byte rows, sized from the map length. The key is freed.

A key whose capacity word is 2^63, the niche of the iterator's None, ends the first pass: the remaining keys get no test, and are freed in the second loop. A real String cannot have that capacity, so this is compiler output, not a behaviour of the action.

### Second pass: write

For each row on the list: `number / 10000` must be below the table length, or an unwrap panic on tag 0x141. If row +0x30 differs or the rest is past the row count, tag 0x60 `Asset {} is out of range.` is built and dropped through the copy's drop helper, so the row is skipped and the call still succeeds. If the byte differs, it is stored and the 12 time bytes at exchange +0x60 go to asset +0x1c. An equal byte keeps its time. Then tag 0x186.

The first pass writes nothing, so a failure at any key leaves the exchange unchanged. All keys are freed in order in both outcomes. Skipped rows need a table whose row positions and numbers disagree, which a healthy table does not have (inference).

### Result bytes

Tags 0xe6, 0xe7 and 0x186 write 2 bytes. Tag 0xe0 writes 0x20 bytes: the low 6 bytes of 0x20a1a0 at +2, left from the stack, and the String at +8. Tags 0x141 and 0x64 copy the 0x60-byte helper result, so stale stack bytes reach the result. Tag 0x143 copies stale spill slots, r13 and rbp, also unset bytes for that tag. The tool snapshots the source at 0x273ba44 and 0x273baaf and compares all 0x60 bytes.

### Status text

- 0x141 `Invalid perp DEX`
- 0x143 `Invalid input length`
- 0xe6 `Growth mode cannot be set when deployer fee scale is more than 1`
- 0xe7 `Growth mode blocked by validators`
- 0xe0 parts `Error deploying perp: `, value; the value is built from `can only change growth mode once every `, f64 30.0 at 0x20a1a0, ` days`
- 0x60 parts `Asset `, value, ` is out of range.`
- 0x64 parts `Unknown coin `, value

The 0xe0 text says 30 days on every chain, while the wait is 60 s unless the mode byte is 3.

### What the byte does

Serializer 0x37585e0 prints `enabled` for byte 0, `disabled` for byte 1 and `blocked` for any other byte, read from 3 `lea` sites, with 7, 8, 7 length immediates.

In 0x37130b0, the perp fee producer of `fees-trade-fee-94` (open), 0x3713146 loads the byte and `test r13b,r13b; sete al` at 0x3713225 indexes the table at 0x204350, which holds 1.0 then 0.1. So byte 0 picks 0.1 and any other byte 1.0. This packet pins those bytes and constants and does not run that function. `fees/compute.rs` line 195 says the same.

So `true` selects the 0.1 factor, and rule 8 refuses it while the dex scale is above 1. `fees-fee-scale-94` (open) holds the same rule from the other side: a scale above 1 is refused with tag 0xe6 while any asset of the dex has byte 0. Together they keep byte 0 and a scale above 1 apart, except for a status 3 row, which skips rule 8.

This answers the next question of `fees-fee-scale-94`: 0x273b79c and its 2 copies are rule 8 here.

### Inferences (not proved by these bytes)

- Mode byte 3 means mainnet, by the `Action only allowed on testnet` gate in `fees-start-trial-94` (open). So mainnet waits 30 days.
- The action is `setGrowthModes`. The name is at 6 places in .rodata, and each caller is the perp deploy function whose arm calls the fee scale setter in `fees-fee-scale-94` (open). The arm before the setter was not traced.
- Byte 2 is set by a validator vote, from the text of tag 0xe7. No writer of byte 2 was found, and this setter never stores it, because its new byte is 0 or 1.
- The Rust type of the key list is a BTreeMap of String to bool, from the leaf layout and the iterator shape.

### Reference comparison

`reference-diff.tsv` has 8 rows. The reference has no action or setter for growth modes. It names the three values `normal`, `allowHip3`, `frozen` where the serializer prints `enabled`, `disabled`, `blocked`, and treats byte +0x29 as a bool `growth_mode_allowed` in `asset/pdi.rs`, a name that does not fit a 3-valued byte whose zero value turns on the 0.1 factor. The `fees/compute.rs` line about the clear byte agrees with the bytes.

## Implementation and comparison

No Rust implementation: not yet implemented. The comparison here is byte evaluator against a separate closed-form Python model.

- Vectors: 7860, mismatches 0, 2620 per copy. Groups and outcomes are in `evidence.json`, one line per vector in `vectors.tsv`.
- Real code: the 3 setters, 0x3332080, 0x3332270, 0x374a1a0, the time add 0x1459ca0 and 2 chrono helpers.
- Stubs: map iterator (arguments and all 9 iterator words on the first call), dex set (arguments, empty on first use), drops (tag and payload), allocator, copy, free (pointer, size, flag), format (pieces, value pointer, formatter), byte compare, panics (location and arguments).
- Caller-saved registers are spoiled by stubs, unset bytes in strict arenas fault, and state arenas hold a position-dependent pattern. The check compares the whole result, the whole exchange, all rows, metas and assets, the free order, the list rows, and drop and allocation counts.

Mutation survey over copy A and the 3 helpers, using the copy A vectors: 382 mutants, 370 killed, 12 equivalent with a reason each in `evidence.json`. Copies B and C were not mutated: their bodies match copy A row by row and all vectors run on them. The first survey left 4 real vector gaps, closed by more keys after a niche key, a zero word at row +0x18, a dex number of 100000 and a check of the empty name pointer.

## Results and limitations

- Passed: 7860/7860 vectors, 370/382 mutants killed plus 12 equivalent.
- The real iterator and dex set are not run, so the key order is the order the stub gives (sorted, in the vectors) and the set is modelled as exact. Those helpers have their own copies per setter.
- The action arm, its dispatch and the authority check before it are not covered, so who may call this is unknown here.
- The equivalence of the survivors is an argument plus no tested input telling them apart, not a proof.
- 0x37130b0 is pinned, not evaluated. The spot path was not checked for the same byte.
- No progress gate is requested.

Next question: which writer stores byte 2 at asset +0x29 (tag 0xe7 `Growth mode blocked by validators`), and does a vote action hold it?
