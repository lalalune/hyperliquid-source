# staking: cSigner jail, unjail and jail votes in node #94

This packet shows how node #94 jails and unjails a signer, so a reconstruction can write the `cSigner` action body and the `jail_until`, `signer_to_last_manual_unjail_time` and vote tracker rows from bytes: `unjailSelf` has two time gates and a list that skips them, `jailSelf` records no time, and `voteJail` jails after strictly more than 2/3 of the stake has voted, until the stake-weighted median of the voted times. The reference tree has no body for this action (`impl_execute_action.rs` only says "nested signer-operation switch").

- Component ID: staking (Staking and validator lifecycle, `l1/staking.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead only. Nothing is copied from it.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are the whole functions `0x3993800`, `0x3992850`, `0x398faa0`, `0x39416f0`, `0x3597650`, `0x3bb1c70`, `0x3386c30`, `0x33a4f60` and `0x33bc340`, the serde key rows that name the state fields, the per-chain list jump table and the call sites of these functions. Excluded: the wrapper rows of RE-010 discriminant 176 and the two sites inside the validator profile path, which belong to other packets. They appear here only as site addresses. Callees are stubs with argument checks (list below).

## Reproduce

From the repository root:

```
python3 tools/c_signer_jail.py --out research/work-items/staking-c-signer-jail-94
python3 -m unittest tests.test_c_signer_jail
```

The tool takes about 4 minutes with its 4 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. Its bytes are only read, and an interpreter inside the tool evaluates them.

Generated files: `evidence.json`, `function-rows.tsv`, `callers.tsv`, `constants.tsv`, `field-names.tsv`, `status-text.tsv`, `chain-lists.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses in `artifacts/node/94/hl-node`. Function bounds are FDE bounds. Slots are read from `.rela.dyn`. Analysis of the nine functions is complete for the reached rows. `evidence.json` lists the unreached rows of each function, and the groups are named under Results.

### State and action

`S` is the state at Exchange `+0x8f8`. Exchange `+0x8f2` is the chain byte and `+0x60` the 12 byte block time, as the action wrapper passes them. The serializer at `0x39909b6` onward names these offsets (`field-names.tsv`):

| Offset | Key | Shape |
| --- | --- | --- |
| `S+0x120` | `allowed_validators` | set of 20 byte keys |
| `S+0x138` | `broadcasters` | set of 20 byte keys (not used on this path) |
| `S+0x150` | `validator_to_profile` | map, value 0x58 bytes, signer at value `+0x40` |
| `S+0x1b0` | `jail_until` | map address to time |
| `S+0x1c8` | `signer_to_last_manual_unjail_time` | map address to time |
| `S+0x290` | `allow_all_validators` | byte |

A time is 12 bytes: `i32` packed date, `u32` seconds, `u32` fraction, compared in that order with the date signed. Node layouts for all six tree kinds are in the `Layout` rows of the tool.

The action tag byte is 0 `unjailSelf`, 1 `jailSelf`, 2 `voteJail`. `voteJail` has the signer at action `+1` and the time at `+0x18` (`struct variant CSignerAction::VoteJail with 2 elements`, `variant index 0 <= i < 3`).

### Active signer gate `0x3992850` (1715 bytes, slot `0x57738f0`, 4 sites)

The RE-010 wrapper for discriminant 176 writes status `0x95` when this gate is false, before the body runs.

| `allow_all_validators` | Rule |
| --- | --- |
| nonzero | signer is a key of the stakes returned by `0x3c10fa0` for the current round |
| zero | some key of `allowed_validators`, in order, has a `validator_to_profile` row whose value `+0x40` equals the signer |

The list form compares the profile signer and never the validator key. A key with no profile is skipped. Each row builds and drops one `0x91` status.

### Body `0x3993800` (5223 bytes, slot `0x57738f8`, 3 sites)

`unjailSelf`:

| Order | Check | Result |
| --- | --- | --- |
| 1 | signer not in the set at `S+0xd8` | `0x186`, nothing written |
| 2 | per-chain list, mapped by `0x3bb4f30`, contains the signer | leave the set, `0x186`, no time read or written |
| 3 | `jail_until[signer] > now` (equal passes) | `0x9c` with the 12 byte time at result `+4` ("Jailed until") |
| 4 | row of `signer_to_last_manual_unjail_time`, a new row holds 1970-01-01 00:00:00 | row stays even if the next check fails |
| 5 | row + 300 s > now (equal passes) | `0x9b` ("Can only manually unjail once every 300 seconds") |
| 6 | row = now, leave the set | `0x186` |

Step 5 uses `chrono` time and date add through slots `0x576e8a8` and `0x576e8b0`. A day carry outside `i32` days or a failed date add panics with `` `NaiveDateTime + TimeDelta` overflowed ``. The text prints the f64 `300.0` at `0x20a3e8`, the code uses the immediate at `0x3994a0b`.

`jailSelf` calls the jail helper with no time and returns `0x186`, whatever the helper did.

`voteJail`:

| Order | Check | Result |
| --- | --- | --- |
| 1 | `0x37d9df0` returns no current row | `0x186`, nothing written |
| 2 | target in the per-chain list | `0x186`, nothing written |
| 3 | voter has no key in the current stakes | no vote is written, still `0x186` |
| 4 | tracker row for the target | new row has `+0x18` byte 0 and `+0x19` byte 1, new inner row has empty maps |
| 5 | tracker `+0x18` byte nonzero | vote upsert only |
| 6 | quorum before, vote upsert, quorum after | fires only on a false to true change |
| 7 | fire | `+0x18` word becomes 1, then the row is removed, votes become (time, stake) rows |
| 8 | rows sorted by (time, stake) | walk until `2 * running >= total` or `running >= 2^63`, take that time |
| 9 | jail helper for the target with that time | `0x186` |

Votes of keys that left the stakes are dropped at step 7 and count for nothing at step 6. A later vote by one voter replaces the earlier one. The running sum saturates, the total is a checked add that panics. The sort is `0x3386c30` for 2 to 20 rows and the slot `0x5776250` sort from 21 rows. A vote row with date 0 ends the row list.

Between steps 6 and 7 the body tests `len >= 101` on the tracker map at `S+0x88`, collects up to 100 keys through `0x3bda450` and frees that vector unread. This path does not limit the map. Fired rows are removed, unfired rows stay.

### Jail helper `0x398faa0` (1673 bytes, 4 direct sites)

1. Build the list set: chain byte 3 reads the static at `0x5786238`, other chains call `0x33de620`.
2. If the target is in the list and any key of the set at `S+0xd8` is in the list, drop out with no change.
3. Insert the target into the set at `S+0xd8`.
4. Open `jail_until[target]`, a new row holds 1970-01-01 00:00:00.
5. With a time present and later than the row, write it. So `jail_until` only moves forward, and `jailSelf` leaves it alone.

The body and the helper disagree on chain 3: the body calls `0x33de620`, whose table gives cell `0x5786218` on chain 3, and the helper reads `0x5786238`. Chain 0 panics with `invalid chain` in `0x33de620` (`chain-lists.tsv`).

### Quorum `0x3597650` (1863 bytes, slot `0x5775db0`) and `0x39416f0` (302 bytes, 2 sites)

`0x39416f0` turns the vote keys into a set and calls `0x3597650`. With `T` the checked sum of all stakes and `S` the checked sum over voters found in the stakes: false if `T >= 2^63`, false if `3*S` overflows 64 bits, else `3*S > 2*T`. An empty stake map gives false. A sum that overflows panics. This is not the 128 bit compare of `0x3366b60`. It then loops over the second map at inner row `+0x18`, and `0x330eaa0` is a no-op while that map is empty.

### Row builders

`0x3bb1c70` (1125 bytes) collects the rows, 0x18 bytes each with the time at `+0` and the stake at `+0x10`, starting at capacity 4. `0x33a4f60` (647 bytes, 6 sites) replaces or inserts one address to time row and returns the old value. `0x33bc340` (2 sites, FDE size in `evidence.json`) opens an entry, a vacant row takes date 719163 days from `0x151f6f0`.

### Stubs

Every callee outside the nine functions is a stub with argument checks: `0x37d9df0`, `0x37d5e10`, `0x3c10fa0`, `0x33de620`, `0x3bb4f30`, `0x3bb59c0`, `0x33b0f60`, `0x33eb3e0`, `0x33c2190`, `0x33c2490`, `0x33aa7c0`, `0x33aab70`, `0x33ad2f0`, `0x33a64c0`, `0x2f5f150`, `0x32d6a00`, `0x3bda450`, the drop functions, the allocator, the sort at slot `0x5776250`, `chrono` add and date from days. The trees are real nodes, the bytes of the targets walk them. The two sets in the state are read by real rows, but insert and remove are stubs that only record the call.

### Inferences

- The per-chain list holds foundation validators, because `0x3bb4f30` walks `validator_to_profile`. Its content is not read here and the name comes from the reference term `foundation_self_signers`.
- Chain byte 3 is Mainnet.
- `S+0xd8` is `jailed_signers` and `S+0x88` is `jvt`. The serializer passes `S+0xb0` and `S+0x70` to the key rows for these two fields, so the map offsets are 0x28 and 0x18 inside those fields, which this packet does not prove.
- The list skip in step 2 of the helper keeps at most one list member jailed.
- The dead scan is a leftover of a removed log or limit.

### Unresolved

- Content of the three static lists and of the static at `0x5786238`. Why chain 3 has two statics.
- The second map at inner row `+0x18`. It is always empty in these fixtures, and rows that touch a non empty map are unreached.
- The time the validator profile path passes at the two helper sites `0x39958a0` and `0x3995d46`.

## Implementation and comparison

Not yet implemented. No Rust source is included. The spec class in the tool is an independent statement of the rules above and is only a test oracle.

## Results and limitations

- Named cases 254: active_signer_gate 25, c_signer_body 160, jail_signer 42, stake_quorum_two_thirds 27. Vector cases 480. All of them match the rule list on status, 12 byte time, call events, the three maps in order, and a digest of every state word outside those maps.
- Mutation sweep: 935 edits of reached conditional rows, immediates and field offsets, 820 killed, 115 survived. Each survivor carries its group in `mutations.tsv`. The groups are below, and the `open` group is not explained.
  - 58: open: no named case tells this edit apart and it was not analysed further
  - 16: zero stored into a frame or iterator word that the stub on this path does not read
  - 12: bound of the unrolled eight step tree descent: it picks between two walks of one path and no tree here is that tall
  - 11: copy or read of the second inner map words, which are zero in every fixture
  - 8: state word of the loop at 0x3993a77 or of its earlier clone flag: the body runs once, so the edit changes no path
  - 6: first leaf length: only tested against a slot of 0, and a leaf reached with rows left has a nonzero word at both offsets
  - 3: constant argument of the lazy cell call, which the stub does not read
  - 1: low byte of the empty time word of jailSelf: a date of 1 is below every stored row, so the row keeps its value
- Unreached rows: 374 of 2917 rows. They are the unrolled 8 step tree descents for trees of height 8 or more, unwind landing pads, panic arms, the clone of a non empty second map and the block that drops an earlier clone (the `0x158` flag): the loop at `0x3993a77` runs its body once, so that block has no entry on any path read here.
- Stubbed behavior is assumed, not proven. The jvt tree in the 101 row cases is a small tree with a raised length word, so `0x3bda450` is a stub. Tree splits are out of scope: `0x2f5f150` inserts into a leaf with room.
- No progress gate is requested.

Next question: which time does the validator profile path hand to `0x398faa0` at `0x39958a0` and `0x3995d46`, and what do the heartbeat jail rows write into the set at `S+0xd8`?
