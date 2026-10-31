# bridge: validator set update votes and the epoch move in node #94

This packet shows that a validator set update is two vote maps keyed by one `u64` epoch, with no stored set and no event id, and that the only effect of a finalize quorum is `current_epoch = action epoch` plus removal of signature rows with a lower key, so a reconstruction can build `validator_set_signatures`, `validator_set_finalized_votes` and the epoch move from the bytes: a signature for a past epoch is stored, a finalize for an epoch at or below the current one returns success and changes nothing, and neither map is ever cut to 100 rows.

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`; handler arms 29 and 45 of RE-010)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for bytes, branch order, constants, status text, serde keys, node layouts and call sites; inference for the action names, the word epoch and the meaning of the byte at row `+0x19`; unresolved items are under limits
- Scope included and excluded: included are 29 functions run as real bytes (`path.tsv`), from the arm wrappers `0x1e642e0` and `0x1e64cb0` through the cores `0x374e620` and `0x374f930`, amount limits `0x37a1230`, set compare `0x3369db0`, the two trackers `0x3945250` and `0x3945a20`, the quorum and stake test, and the signature prune `0x3942a90` with its tree split and row drop. Excluded, and stubs here: the set builder `0x3366580` (body bound by #98; this packet feeds its outputs in), the request builder `0x358ea60`, hash helper `0x37f2940`, signature recovery `0x14c6f50`, the unique-validator lookup `0x33690c0` (#133, #425), the stake map builder `0x3364ed0`, the key set builders `0x3bb29c0`, `0x3bb2dc0`, the leaf inserts behind the vacant entries, the clones and drops. Deposit votes (`0x3947510`) are not read here. `0x3366b60`, `0x3367530`, `0x3940d60`, `0x339b0d0`, `0x339e610` are shared with the withdrawal votes and run as real bytes, but they are not the subject of this packet and only `0x3941240`, the other copy of the quorum, is mutated here.

## Reproduce

```
python3 tools/bridge_validator_set_votes.py --out research/work-items/bridge-validator-set-votes-94
python3 -m unittest tests.test_bridge_validator_set_votes
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes of each function, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes about 4 minutes, most of it the mutation sweep.

## Evidence

Addresses are virtual addresses. Instruction rows are in `function-rows.tsv`; every function ends exactly at its FDE end. Rows quoted below are bound in `key-rows.tsv`, so a moved row fails the run.

### The path

```
arm 29  wrapper 0x1e642e0   clone the set, chain byte state +0x8f2
  core 0x374e620            voter, amounts, hash, recover, signer, set compare
    tracker_sign 0x3945250  row by epoch, store signature; quorum 0x3941240 -> stake test 0x3366b60
arm 45  wrapper 0x1e64cb0   clone the set
  core 0x374f930            voter, amounts, set compare, epoch test
    tracker_final 0x3945a20 row by epoch, store voter; quorum 0x3940d60 -> stake test 0x3366b60
    on quorum: current epoch := action epoch; prune 0x3942a90
```

`validator_set_signatures` and `validator_set_finalized_votes` are named by the serializer `0x22155c0`, not by the reference: the helpers `0x22bdba0` and `0x22bd840` load the key text and `0x221576c`, `0x2215788` pass the field (`fields.tsv`). With the bridge at state `+0x3398` they sit at bridge `+0xa0` and `+0xd0`, and the trees are at `+0x18` inside each. The word at context `+0x48` (state `+0x3840 + 0x48`) is the epoch that the voter lookup, the member test and the stake test read; the reference calls it `current_epoch`.

An action is a set tree `(root, height, length)` at `+0`, the epoch at `+0x18`, and for arm 29 a `0x48`-byte signature at `+0x20`. The set is keyed by `0x30`-byte entries: `u64` stake, then two 20-byte addresses, ordered in that order.

### Row shape

A row key is one `u64` (`0x3945418`, `0x3945bc8`), in nodes of `0x1c8` bytes. The value is `0x20` bytes: `+0` a map, `+0x18` done byte, `+0x19` open byte. A new row is done 0, open 1 (`0x394550b`, `0x3945cb9`); the quorum move writes the word 1, so done 1, open 0 (`0x394566d`, `0x3945e0e`).

The map at `+0` has no key: its nodes hold only `0x30`-byte values, so it has one entry or none. The trackers walk to the first leaf and use entry 0, or create it. That entry is the voter map at `+0` and a second tree at `+0x18`. This is the tracker shape of `0x3942d90` with a unit type where the withdrawal path has `(amount, destination)`: the voted set is not stored, and the set compare before the tracker is the only link between a vote and a set. Node layouts are in `node-layouts.tsv`.

### Status order

Status text comes from the Display table `0x59a8d0` (`status-text.tsv`). The wrapper turns `0x186` into outcome tag `13`, and any other status into tag `14` with the status at `+8`.

| Status | Text | Arm 29 step | Arm 45 step |
|---|---|---|---|
| `0x97` | Epoch state does not exist | 1 (current epoch) | 1 |
| `0x2a` | User is not a validator. | 1 | 1 |
| `0x13f` | Invalid input number | 2: first stake at or over the limit, in key order, then the epoch | 2 |
| `0x7a` | Unable to recover signer. | 3: hash helper error, 4: recovery error | not on this arm |
| `0x11f` | Signer does not match expected user | 5: 20-byte compare with the outer signer | not on this arm |
| `0x35` | Validator set does not match L1 validator set. | 6 | 3 |
| `0x97` and other statuses of `0x3366580` | passed through whole | 6 | 3 |
| `0x186` | success | 7 | 4 |

`limit` is `0x0ccccccccccccccc`, `i64::MAX / 10`, one `movabs` at `0x37a1247` with two compares (`limits.tsv`); `amount >= limit` is refused and the payload is the refused word. The set compare needs equal lengths, then equal entries in order (stake, 20 bytes at `+8`, 20 bytes at `+0x1c`), then the epoch returned by the builder equal to the action epoch. Any miss is `0x35`. `scenarios.tsv` has the outcome of every run, including the order pairs such as `sign_order_hash_before_set`.

Arm 29 asks for a request of kind 4 (`0x374e8ff`) with the set and the epoch, and passes the chain byte at state `+0x8f2`. Arm 45 reads no signature: its action has none (`final_reads_no_signature`).

### Epoch rules

Arm 29 has no epoch test. A signature for an older or equal epoch is stored as long as the builder returns a matching set for that epoch (`sign_old_nonce_accepted`, `sign_current_nonce_accepted`).

Arm 45 compares after the set compare: `action epoch <= current` leaves with success and no change (`0x374fa27`, `final_old_nonce_is_noop`). So a wrong set for an old epoch still gets `0x35` (`final_set_differs_old_nonce`), and a missing epoch state still gets `0x97` (`final_set_lookup_failure_old_nonce`).

A newer epoch does not need to be current + 1 (`final_skips_epochs`). Votes for two epochs do not add (`final_two_nonces_separate`). After a move, a lower epoch with a live row is dead: its votes hit the epoch test (`final_lower_after_higher`).

The stake test is `2 * total < 3 * voted` of the epoch current at the vote, strict (`final_exact_two_thirds_short`). When the row moves, in this order, with no read of the signature row:

1. `0x374fac4` stores the action epoch at context `+0x48`.
2. `0x374fadf` calls `0x3942a90` on the signature tracker with the action epoch.

The Once word `0x577ab98` is tested between the quorum and the store; it starts as 3 in the file, and here the call is a stub. The next vote already uses the new epoch for the voter lookup, the member test and the stake (`final_after_move_old_signer_refused`), and an epoch with no state refuses everyone with `0x97` (`final_after_move_no_epoch_state`).

### Prune

`0x3942a90` splits the tree at the key with the real `0x2fb3980`. The upper part, keys at or above the epoch, becomes the map, so the row of the winning epoch stays (`final_keeps_equal_row`). The lower part is drained: `0x3be5020` runs `0x3941820` on each row and writes each key into an output vector, which arm 45 frees unread (`prune_voted_rows`). `0x3941820` only tests that the second tree of a finished row is empty, and the drop follows.

The finalize map is not touched, so its rows stay after the move (`final_row_kept_after_move`).

### The row count step

Both trackers end with `if len >= 101`, build a key iterator, and call `0x3bd21a0` with 100. The only rows after the call are a capacity test and a free (`row-count-note.tsv`). No row is removed: with 101 rows the map still has 101, and 800 bytes are allocated and freed (`no_trim_101_rows`, `final_map_101_rows`). This is the same no-op as in the withdrawal trackers.

### Copies

Slots `0x57731a8` and `0x57731b8` hold the two cores; each has three callers (`slots.tsv`, `call-sites.tsv`). `0x46bd130` and `0x46bdb40` have the same rows as the wrappers. `0x46bd270` and `0x46bdc30` have the same shape with one or two rows that use other state offsets (`wrapper-copies.tsv`). The copies were not run.

### Reference compare

`l1/exchange/handlers/29_sign_validator_set_update.rs` and `45_vote_eth_finalized_validator_set_update.rs` have the shape of this path. These points differ from the bytes:

| Reference | Bytes |
|---|---|
| Vote maps keyed by `EthEventId`, arm 45 has a `header` | One `u64` key, the action epoch; the action has no other key field |
| Arm 29 order: signer, set compare, hash, recovery | Voter, amount limits, hash, recovery, signer, and the set compare last |
| Arm 29 has no amount limits | `0x37a1230` runs on both arms, before any hash |
| Inactive signer is status 148 | `0x2a` or `0x97`, from the lookup |
| The signature tracker stores the set and clears votes when it differs | No set is stored; the bucket has a unit key |
| Finalize vote: `inserted && quorum` | Quorum read before and after the insert; a move needs false then true |
| Maps are cut to the newest 100 rows | No removal |
| Quorum writes the epoch into an auxiliary marker set | No such write: the second effect removes signature rows below the epoch |
| Entry fields named validator, then signer | The first address is the one the lookup `0x33690c0` matches against the signer (value `+0x18`, read, not run here) |

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the status, payload words, stub events, epoch and full tree state after every operation.

## Results and limitations

- 112 named scenarios (229 operations) and 200 generated scenarios of 12 operations: 0 mismatches.
- 517 byte edits on reached rows of 13 functions (condition, immediate; displacement on six of them): 409 killed, 108 survived (`mutations.tsv`). Each edit runs only the named scenarios for its function, to bound the time. Survivors carry a class label per function: these are reviewed classes, not a proof that each edit is equivalent, so a survivor is a row this packet does not constrain. An unedited image must pass under the same step limit first.
- Reached rows: 1336 of 4895 rows are not reached (`unreached.tsv`). They are panic tails, allocation failures, landing pads, rows for trees deeper than two levels, and the paths named below.

Limits:

- `0x3366580` is a stub, so the set an epoch yields is a fixture input. That its stake is a sum over the validator's map at value `+0`, and that the two addresses are value `+0x18` and `+0x2c`, rests on reading that body, not on running it here. #98 binds that body.
- `0x33690c0` is a stub, so statuses `0x97` and `0x2a` are fed in.
- `0x3364ed0` is a stub, so stake values are fixture inputs.
- The tree split and the iterator run for real on trees of height 0 or 1. Leaf inserts are stubs, so a node split on insert is not run, and fixture rows stay below 12 per leaf when voting.
- The second tree in each bucket stays empty in every run; a non-empty one reaches a no-return call. What it stores is unresolved.
- The meaning of the open byte at row `+0x19` is unresolved beyond its writes and the one read in `0x3941820`.
- Slot `0x576e8b8` is a stub that returns, so what the Once at `0x577ab98` sets up is unresolved. Nothing on this path reads the cell.
- Arm numbers and action names come from RE-010 and the reference. The cores have no direct caller; they are reached through the slots.
- The wrapper copies were compared by rows and not run.
- What runs the two arms on a live node, and who supplies a set for a future epoch, is outside this packet.

No gate is requested.

Next question: read the deposit tracker `0x3947510`, whose quorum `0x3940ea0` adds a second test on 20-byte addresses, against these rules.
