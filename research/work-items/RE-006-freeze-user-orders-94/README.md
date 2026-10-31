# RE-006: what a token freeze does to a user's orders and TWAPs, and which check stops the next order

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inference and unresolved items are marked.
- Scope included and excluded: included are the three freeze handler copies, the per-spot sweep order, the TWAP sweep of one user on one spot, the frozen predicate, the action asset list, the gate block in three hosts, and the writer of the token spot list. Excluded are the deployer check before the handler, the bodies of the user-wide cancel wrappers (open #161), the row flush bodies, and the asset resolver.

## Reproduce

From the repository root:

```
python3 tools/freeze_user_orders.py --out research/work-items/RE-006-freeze-user-orders-94
python3 -m unittest tests.test_freeze_user_orders
```

The tool takes about 90 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs.

### The handler

Three copies: `0x274b550`-`0x274b7dd` (first), `0x4d69da0`-`0x4d6a068` (second), `0x4d6a070`-`0x4d6a338` (third). Each has one direct caller, `0x23e7fb3`, `0x4ad8483` and `0x4ad7b53`, inside the three spot deploy hosts. The call takes the token from action `+0x08`, the user from `+0x10` and the flag byte from `+0x24`. The host first compares the token with the list length and writes status `0xea` when it is past the end (`action_fields` in `evidence.json`), so the panic inside the handler has no route from these call sites.

Order of the checks, on all three copies:

1. Token row at metadata `+0x180`, stride `0xe8`. A token past the list panics at `l1/src/spot_meta.rs:119`.
2. Row `+0x10` must be the word 1. Otherwise status `0xdf` with `already revoked token freeze privilege`. This stops freeze and unfreeze alike.
3. Flag byte 0 (only the low byte of `r8` is tested): the user leaves the set through `0x33acfe0`, status `0x186`. Orders are not touched and the cap is not read.
4. Flag nonzero: set length at row `+0x28` must be below 1000, unsigned 64-bit. Otherwise status `0xdf`. The cap check runs before the insert, so a user already in a full set is also refused.
5. Insert through `0x339b590`. Its result is not read.
6. The spot list at row `+0x58`/`+0x60` is cloned into a new block, and the walk reads the clone.
7. For each spot, in list order:
   - a spot at or past the book list length panics at `l1/src/books.rs:19`;
   - user-wide cancel wrapper with book `spot * 0xd8`, flag 1, reason `0x10`;
   - TWAP sweep with flag 1 and the same spot, writing into the same row vector;
   - row flush, which takes the vector by value. The vector restarts empty for the next spot.
8. The clone is freed and the status is `0x186`.

Copies differ as follows. Second against third has the same 165 instructions: 3 field rows and 3 call target rows in `copy_diff` (`+0x3e08`/`+0x3e10`/`+0x3f60` against `+0x3388`/`+0x3390`/`+0x34e0`). The first copy has 152 instructions and no size overflow check before its allocation. Its order of effects is the same under every case that runs on it.

The worked example in `evidence.json` runs token 3 with spots 4 and 6: insert, clone, then sweep, TWAP and flush for 4, then for 6, then free.

### Cap text

The cap message at `0x5998cd` is 53 bytes: `number of frozen users capped at {MAX_N_FROZEN_USERS}`. The braces are in the ELF, so the user sees them. `l1/exchange/handlers/26_spot_deploy.rs:656` has a different text, and `l1/spot_meta.rs:887` has this one.

### TWAP sweep of one user on one spot

`0x42f4680` and `0x42f4bf0` (same 277 instructions and the same callees; the first copy `0x26ddbe0` has the same shape with other callees, rows in `copy_diff`). The tracker is state `+0x3f60` in the second handler copy and `+0x34e0` in the others.

- User map at tracker `+0x18`, keys 20 bytes. An absent user returns at once.
- Collector `0x486b870` lists ids in key order. With flag 1 it keeps a row only when the row's first word equals the spot. The handler always passes flag 1.
- For each id: look the user up again, take the row through `0x4944230`. A missing row or user drops word `0xce` and goes on.
- When the user's map length reaches 0, the user leaves through `0x49463e0`.
- The row is built by `0x46ca2b0` from state `+0x90` and pushed with tag 4, word `0x8000000000000001`, the id, the time at state `+0x60` and the user. Row stride `0x268`.

Rows on other spots stay, and so does the user. TWAPs of the user on other spots are not touched by that step.

### Frozen predicate

`0x375f1c0(metadata, user, spot)` is reached only through slot `0x57739d8`. A whole-`.text` scan of `FF 15` finds 3 call sites. It reads the spot row (stride `0x20`, base at `+0x00`, quote at `+0x08`). It returns 1 when the user is in the frozen set of the base token or of the quote token. A token counts only when its row `+0x10` is the word 1. Panics are `l1/src/spot_meta.rs:565` (spot) and `:113` (token).

### Gate block

Each of the hosts `0x2208580`, `0x444b430`, `0x444c310` holds one block. The first runs `0x2208a0e`-`0x2208d33` here:

1. Slot `0x57739d0` gives an optional set of 32-bit assets from the action. None passes the block.
2. For each asset, resolver slot `0x5773950`. A status other than `0x186` ends the action with that status.
3. Only result word 1 goes on. Predicate slot `0x57739d8` with the 20-byte user at `+0x3` of the record the block is handed, and the result index. That this user is the acting user is an inference.
4. True writes status `0x158`, `User actions frozen for token` through Display `0x37ffd40`. The remaining assets are drained first.

`evidence.json` `gate` holds the three sites as bytes. Hosts 2 and 3 were read through those byte sites and not run.

### Which actions give a list

`0x335ed30` indexes table `0x588bdc` by action tag minus `0x74`. A tag below `0x74` uses index `0x14`. Of 88 rows, 84 return None. Four go to bodies:

| Index | Tag | Body | Name (inference) | Records |
|---|---|---|---|---|
| 2 | `0x76` | `0x3bddf40` | batch modify | stride `0x50`, asset `+0x38` |
| 12 | `0x80` | `0x33e0170` | modify | one asset |
| 14 | `0x82` | `0x33df050` | order | stride `0x38`, asset `+0x20` |
| 35 | `0x97` | `0x3576f00` | twap order | one asset |

All four keep an asset when it is at least 100000000 or in 10000..109999. Other assets are left out, and an empty result is None. The batch body alone has a length limit: above 10000 entries it builds status `0x143` (`Invalid input length`), drops it and returns None, so the rejection is left to the batch handler. `l1/exchange/handlers/02_batch_modify.rs:152` says that handler rejects this length before any state change. That handler is not run here.

### Who writes the token spot list

`0x375eeb0` is the spot registration. All its checks ran: at most 10000 spots, base differs from quote, base is not token 0, quote is in the map at `+0x250` with byte not 1, base in range, no pair in either order, first spot is base 1 named `PURR`. On success it appends the spot to the rows and to row `+0x50`/`+0x58`/`+0x60` of the base token only. The quote token's list is not written. Combined with the walk above, the walk covers only spots whose base is the frozen token, while the predicate tests both tokens.

### Layout

`evidence.json` `fields` lists the state, metadata, spot row, token row and action offsets, and `node_shapes` lists four B-tree node shapes.

### Observations against the reference

`reference_claims` in `evidence.json` lists 7 rows. Main points:

- `remove_user_orders_for_freeze` in `26_spot_deploy.rs:292` is abstract. Its body is inside the handler, as three calls per spot. `l1/spot_meta.rs:566` names two hooks and leaves out the TWAP sweep.
- `l1/abci/state.rs:8` labels `0x2208580` a peer state response handler, and `:625` describes `0x444b430` as a record mapper. Neither label describes the gate block inside them.

### Inferences, kept apart from the above

- Reason `0x10` is `internalCancel`, from the status table work in open #161.
- Action names come from the file numbers in `references/can1357-hl/l1/exchange/handlers` and the record shapes. No string ties a tag to a name here.
- Result word 1 from the resolver means a spot. The resolver bytes write 1 on its 10000..109999 and `>= 100000000` paths and 0 on the perp paths. It was read by eye and stubbed here. Whether assets at or above 100000000 are spot rows in the usual sense is unresolved.

### Overlap

The handlers and TWAP sweeps appear in open #161, #271 and #292 only as caller or closure rows. Those packets do not pin what the handlers do. `0x375f1c0`, `0x375eeb0`, `0x335ed30` and its four bodies appear in no open or merged packet. `0x2208580`, `0x444b430` and `0x444c310` appear in `RE-009-storage-state-roots` and open #72 only as index rows.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison here is between the real bytes and a specification. A Python evaluator decodes and steps the real instructions. Only edges are stubbed: set insert and remove, the cancel wrappers, row flush, the TWAP take, user removal, row builder and drain, allocation, memcpy, memcmp and the panic slots, resolver, asset list and iterator in the gate. Stubs check their arguments. The collector, its iterator `0x4894610`, the predicate, the accessor and the registration run for real. The specification was written from a read of the code before any run.

| Metric | Value |
|---|---|
| Cases | 258 |
| Runs, counting each copy | 341 (accessor 131, gate 13, handler 87, predicate 27, register 31, twap 52) |
| Mismatches, all runs | 0 |
| Outcomes | accessor: none 107, accessor: some 24, gate: end 7, gate: pass 6, handler: panic alloc failed 4, handler: panic panic 4, handler: status 0x186 15, handler: status 0xdf 7, predicate: 0 11, predicate: 1 12, predicate: panic bounds 2, predicate: panic panic 2, register: panic panic 1, register: status 0x186 15, register: status 0xdf 15, twap: returned 26 |
| Instructions stepped | 484,210 |
| Stepped / total: handlers | 134 / 152, 148 / 165, 148 / 165 |
| Stepped / total: TWAP sweeps, collector | 256 / 277, 256 / 277, 132 / 210 |
| Stepped / total: predicate, accessor, registration, gate block | 130 / 132, 38 / 38, 157 / 157, 95 / 161 |
| Mutants killed / survived / unreached | 474 / 5 / 34 |
| Predicate sites read | 3 |

Across `copy_diff`, second against third handler has 6 rows, TWAP sweep second against third 0 rows, TWAP sweep second against first 7 rows. All TWAP rows are call targets.

Mutants: every conditional jump, `setcc`, `cmov`, immediate and non-stack field offset in the groups of `mutations.tsv` is flipped one at a time, and the cases rerun. The groups are two handler copies, one TWAP sweep, the collector's filter rows, the predicate, the accessor with its four bodies, the registration and the gate block. The 5 survivors and 34 unreached rows each carry a reason in that file.

## Results and limitations

- Passed: all cases against the specification, on all copies listed above, with no mismatch.
- The cancel wrappers and flush are stubs here. This packet pins their arguments, not their effect.
- The block before the gate in the hosts is not pinned: tree at state `+0x8b8` of 20-byte keys, slot `0x57739c8`, status `0x111`.
- The deployer check before the handler is not pinned.
- The first handler copy's TWAP sweep `0x26ddbe0` was only compared by instruction, not run.
- The batch handler's own length rejection is taken from the reference and not pinned here.
- Who calls the three gate hosts beyond their one direct site each is not traced. `call_sites.tsv` has those sites.
- No progress gate is requested.

Next question: what does the state `+0x8b8` address tree do in the same hosts (status `0x111` unless slot `0x57739c8` is true), and does `DeployerSendToEvmForFrozenUser` (status `0x15a`) read the same set?
