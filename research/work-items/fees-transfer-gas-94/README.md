# fees: transfer gas amount on node #94 (0 or 1000000, and a second result)

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository head 1f8c67c63ca4794c9689235471c60297f8a5c985; `references/can1357-hl` used as clues only, nothing copied
- Claim status: observation for all control flow, constants and offsets below; inference where marked; unresolved items listed at the end
- Scope included and excluded: included: the three copies `0x27101a0`, `0x4d00b00`, `0x4d00ea0` and the address test `0x37e51d0`, with the row lookups `0x2755400`, `0x46f2e60`, `0x46f2fe0` running as real bytes. Excluded: how the caller charges the amount (the next call takes it in `rcx`; an open census already lists that function), who writes row byte `+0x3d`, and which keys fill the tested tables.

## Reproduce

From the repository root, no network, no node execution:

```
python3 tools/fees_transfer_gas.py --out research/work-items/fees-transfer-gas-94
python3 -m unittest tests.test_fees_transfer_gas
```

The tool checks the SHA-256 of the binary first and fails on any other input. It uses the standard library only, plus the shared `tools/elf_index.py` and `tools/fde_extents.py`, and starts no external program, so the output does not depend on a binutils version. It takes about 300 s on 3 workers. Output: `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv`, `reference-diff.tsv`. `MANIFEST.sha256` covers these and this README.

## Evidence

Coordinates are virtual addresses. Bounds come from `.eh_frame` FDEs; the table decoder has to land exactly on each FDE end.

| Function | End | Instructions | Role |
|---|---|---|---|
| `0x27101a0` | `0x2710523` | 208 | gas amount |
| `0x4d00b00` | `0x4d00e93` | 212 | copy, lists at `+0x1040`, rows at `+0x11c0` |
| `0x4d00ea0` | `0x4d01233` | 212 | copy, same offsets as the first |
| `0x37e51d0` | `0x37e5346` | 76 | address range test, slot `0x57749e0` |

Signature, observed: `rdi` state, `rsi` address A, `rdx` address B, result in `rax` and `dl` (only `dl` is defined: `mov dl,1` at `0x271050d` leaves the rest of `rdx` as it was). The function writes no state; the vectors compare every state arena before and after.

Order of tests, observed on bytes and evaluated on every vector (`S` is the address test):

1. `S(B)`: result (0, 0).
2. Row of A through the lookup. If byte `+0x3d` is not 0, go to step 9. An absent row gives the default cell, whose builder `0x34d71a0` zeroes bytes `+0x3c..+0x3e` (`0x34d71cc`), so an absent row reads 0.
3. Each entry of the list at `+0x5c0` (stride `0x2f0`): if its table (`+0xf8`, stride `0x78`) has items and holds B, result (0, 0).
4. Table at `+0x318` (stride `0x58`): same test.
5. B is twenty bytes of `0x22` (`0x59c10c`): result (0, 0).
6. B in `0x20 00..00` to `0x20 00..270f`, both ends included: result (0, 0).
7. Token list at `+0x210` empty: panic, `l1/src/spot_meta.rs:113:33`.
8. Token row 0: byte `+0xbc` is 1 and the 20 bytes at `+0xbd` equal A: result (0, 1).
9. `S(A)`: result (0, 0). Otherwise (1000000, 0).

`S(a)` is true on three ranges. All literals carry the first byte, then 11 zero bytes, then an 8-byte big-endian tail (bytes 12..20):

| First byte | From | To |
|---|---|---|
| `0x30` | tail 0 | below 20000 |
| `0x31` | tail 0 | below 10000 |
| `0x32` | tail 0 | 9999 included |

The first two tops use `js` (`0x37e5249`, `0x37e52c3`) and the third uses `setle` (`0x37e5335`), so the third range is closed and the other two are half open.

Step 2 skips steps 3 to 8 entirely: a flagged A pays even towards a known destination, and it does not reach the panic at step 7. Step 1 runs first, so a special B wins over the flag. Step 6 is about B only: the range does not free an A, and `S` does not cover `0x20`.

Callers, by direct `call` scan in `evidence.json`: `0x27101a0: 0x2710979 in 0x2710530 0x2713325 in 0x2712ce0 0x27133c6 in 0x2712ce0 0x2715f0c in 0x2715320, 0x4d00b00: 0x4d01fc8 in 0x4d01b40 0x4d06455 in 0x4d05e10 0x4d064f6 in 0x4d05e10 0x4d0b313 in 0x4d0a6d0, 0x4d00ea0: 0x4d01689 in 0x4d01240 0x4d07c15 in 0x4d075d0 0x4d07cb6 in 0x4d075d0 0x4d0cbe3 in 0x4d0bfa0`. At `0x2712ce0` the amount is stored at `rsp+0x30` (`0x27133cb`) and passed in `rcx` to the call at `0x27137b2`. Status tag `0xf6` has the Display text `Insufficient {} balance for token transfer gas.` (format at `0x1f57b9`, arm `0x3801174` by table `0x59a8d0`).

Inferences, kept apart from the above:

- A is the sender and B the destination. Basis: at `0x2712ce0`, A is the action word at `+0x88`, the same address the next call checks a balance for, and the failure text is about gas. The reference agrees.
- The name "transfer gas" comes from that status text, reached through the next call, not from this function.
- 1000000 is one quote unit at 6 decimals. Basis: the reference, and a `* 100` in the next call; the wei decimals are not read here.
- Steps 3 and 4 read as "destination already has state", so the amount acts as a first-use charge. No byte here names those tables.
- Second result 1 marks the token 0 deployer by inference: a tagged address in token row 0. The caller keeps the byte; its effect is out of scope.

`reference-diff.tsv` compares the reference `compute_first_dex_fee` in `handlers/39_usd_send.rs`: 8 rows differ and 3 agree. The largest differences: the reference stores the tail in bytes 8..16, not 12..20; it gives the `0x32` top as 999999, not 9999; it treats all three tops as closed; it has no second result; it has no `0x20` block in this function and no empty-token panic.

Analysis is complete for the four subjects: every instruction is decoded and 984 of 993 (subjects 699 of 708) are executed by vectors; the 9 left are padding `nop`s.

## Implementation and comparison

Rust implementation: not yet implemented. The comparison here is byte evaluator against a closed-form Python model written separately (`gas_model`, `special_model`), on all three copies.

Stubs, each checking its arguments: the byte compare (length 20, one of the 8 literal blocks, subject A or B), the row hash and address hash (state pointer and key), the once call, the panic (Location record). Real bytes run for all four subjects and the three row lookups. Hash tables are real layouts with decoys, tombstones and probe walls. The stack and state arenas are filled with position-dependent patterns.

## Results and limitations

- Vectors: 3324 (1108 on each of 3 copies), mismatches 0. Outcomes: 1734 0,0, 42 0,1, 1443 1000000,0, 105 panic.
- Mutation survey: 318 mutants over conditionals, field offsets and immediates of the four subjects, 297 killed, 21 equivalent, each with its reason in `evidence.json` and `mutations.tsv`.
- Tests: 44 unit tests pass, including corrupted hash, out-of-range address, NOBITS read and byte mutants.

Limits: the row lookups are evaluated but not surveyed, since an open packet already covers `0x2755400` as a helper. The hash functions are stubs, so hash values are not proved. Writers of row byte `+0x3d` and of the tested tables are not read, so the meaning of steps 2 to 4 stays an inference. Copy `0x4d00b00` was run with state at its own offsets; which state shape it serves is not established.

No progress gate is requested.

Next question: who writes row byte `+0x3d`, and what does a caller do with the second result 1?
