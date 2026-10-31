# vaults: node #94 vault lifecycle from create through vote modify, deposit and share rewrite

This packet gives the order and exact arithmetic of vault creation, vote modification, deposit and
share rewrite, plus the named `Vault` layout. It shows that `version` is really the
`VaultRelationship` enum, that deposits have a leader 5 percent gate, and that shares use the
pre-deposit total, so these paths can now be written from the bytes.

- Component ID: vaults
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository 1f8c67c; reference `references/can1357-hl` used as a label source only
- Claim status: observation for pins, layouts, lists and evaluated results; inference where marked; unresolved items are listed at the end
- Scope included: create (0x2732e60 gates, 0x395af60), vote modify (0x2704b60, 0x3959900), deposit (0x27362b0 arm, 0x395b3a0), share rewrite (0x395a2c0), equity (0x3955e80), lists 0x37e4e50 and 0x37e4fb0, reader 0x39597b0, Vault serializer 0x2340b70
- Scope excluded: the withdraw pair (0x39582c0, 0x395bdd0), 0x3956320, the user `vaultModify` action, the bodies of debit, credit and balance helpers

## Reproduce

From the repository root, Python 3 standard library only, no external programs:

```sh
python3 tools/vault_lifecycle_path.py --out research/work-items/vaults-lifecycle-path-94
python3 -m unittest tests.test_vault_lifecycle_path
```

The tool checks the binary SHA-256, reads ELF bytes, and imports `tools/elf_index.py` and
`tools/fde_extents.py` for sections and FDEs. It never runs the binary. It writes evidence.json,
functions.tsv, callers.tsv, callees.tsv, pins.tsv, layout.tsv, vault_fields.tsv, address_lists.tsv,
locations.tsv, vectors.tsv and outcomes.tsv. All file contents are deterministic.

## Evidence

Addresses are ELF virtual addresses. Function extents are FDE ranges (`functions.tsv`).
Instruction text in `pins.tsv` comes from the small decoder inside the tool, not from objdump,
and each of the 216 rows is compared with a frozen expected string. Unknown encodings raise an
error.

### Names from the binary

`vault_fields.tsv` pairs the 13 keys of the Vault JSON serializer 0x2340b70 with their offsets. The
binary also contains `struct Vault with 13 elements`.

| Key | Offset | Key | Offset |
| --- | --- | --- | --- |
| name | +0x20 | leader_commission | +0x68 |
| description | +0x38 | is_closed | +0xac |
| create_time | +0x78 | lockup_duration | +0x70 |
| vault_user | +0x84 | allow_deposits | +0xad |
| leader | +0x98 | relationship | +0x00 |
| user_states | +0x50 | always_close_on_withdraw | +0xae |
| | | s | +0xaf |

The word at +0x00 is the `VaultRelationship` tag. The variant table at 0x56a0cc0 lists `normal`,
`child`, `parent`. Four facts tie the tag to that enum:

- Serializer key `relationship` receives the struct base.
- The Vault drop 0x3999cb0 frees the set at +0x08 only for tag >= 2.
- 0x395af60 leaves +0x08 to +0x1f unwritten, and the body evaluation checks this on each success vector.
- The modify body sets tag 2 and clears +0x08 and +0x18.

`Result<Vault, _>` uses tag 3 for its error, and `sizeof(Vault)` is 0xb0 from the copy at 0x395b366.

### Create

The host 0x2732e60 tests an action byte. Byte 0 runs the reserve gates.

| Test | Failure |
| --- | --- |
| first captured amount + 10000000000 overflows | code 190 |
| available balance of the leader < that sum | code 325 |
| second captured amount < 10000000000 | code 326 |
| vault key already present in the map | code 0 with the address |

Then 0x395af60 applies these, in this order (evaluated):

| Test | Failure |
| --- | --- |
| initial >= 0x0ccccccccccccccc | code 319 |
| initial <= 99999999 | code 1 |
| name length >= 101 | code 323 |
| name length < 3 | code 3 |
| name length >= 51 | code 4 |
| description length >= 251 | code 323 |
| description length <= 9 | code 5 |

On success it builds a Vault and calls 0x395b3a0 with flag 1:

| Field | Value |
| --- | --- |
| relationship | child flag from the action byte: 0 normal, 1 child |
| leader_commission | 0.1 for normal, 0.0 for child |
| lockup_duration | 86400.0 when the context byte +0x8f2 is 3, otherwise 20.0 |
| is_closed, allow_deposits, always_close_on_withdraw, s | 0, 1, 0, 0 |
| create_time | time argument |

### Vote modify

0x2704b60 finds the vault, or stores code 7. 0x3959900 has no leader check. It reads an action with
exactly 9 fields, which matches `struct VoteGlobalVaultModification with 9 elements`. Options use
tag 0 for u64 values, capacity `1 << 63` for strings and 2 for booleans.

| Step | Test | Result |
| --- | --- | --- |
| 1 | action address != vault +0x84 | code 390, nothing changes |
| 2 | make-parent byte set | tag must be 0 and margin output +0x10 must be 0, else code 390 and stop; then tag 2 with an empty child set |
| 3 | name | >= 101: 323; > 50: 4; < 3: 3; else store |
| 4 | description | >= 251: 323; < 10: 5; else store |
| 5 | lockup | >= 0xccc cut: 319; > 4000000: code 390 and stop; else store as f64 |
| 6 | commission | >= 0xccc cut: 319; > 1000: code 390 and stop; else store value / 10000 |
| 7 | allow_deposits, always_close_on_withdraw | store when not 2 |
| 8 | s | tag must be 1 and both ledgers of the vault address must hold only zero values, else code 390 and stop; then store |

Code 390 is the plain success value. The steps run in order with no rollback. A name stored in
step 3 stays in place when step 5 stops with code 390, and that exit reports success (`outcomes.tsv`).

### Deposit

Every row below is backed by rows of the same group in `pins.tsv`.

| Step | Group | Test | Failure |
| --- | --- | --- | --- |
| Host minimum | entry | deposit byte set and amount < 5000000 | code 41, 0x2736752, in all 3 host copies |
| Flag | entry | hosts pass r9d = 0; 0x395af60 passes r9d = 1 | none |
| 1 | g1 | tag == 1 and depositor != leader | code 22 |
| 2 | g2 | allow_deposits == 0 and depositor != leader | code 23 |
| Total | total | equity(vault_user), plus each child when tag >= 2, saturating | none |
| 3 | g3 | total < 0 and vault_user not on list A | code 9 |
| 4 | g4 | flag 0, tag != 1, depositor != leader, vault_user not on list B: leader share gate | code 2 |
| 5 | g5 | available balance < amount | logged error tag 51, code 44 |
| 5 | g5 | amount has the sign bit set | panic, qtys/mod.rs:843 |
| Move | move | debit depositor, credit vault; context +0x238 goes down and back up by amount | none |
| Rewrite | share | 0x395a2c0(vault, depositor, amount, total from the Total step, time) | none |
| Post | post | depositor record missing | panic, vault/mod.rs:407:58 |
| Post | post | record +0x08 u64 add, +0x10 i64 add, +0x24 time, receipt | none |

Reject codes in the deposit body are stored at output +0x08 under tag 0x8000000000000019. Success
stores tag 0x8000000000000004, amount / 1e6 at +0x08 and the vault address at +0x10.

The leader share gate at 0x395bb4f, as an exact formula (`model_gate` in the tool):

```text
equity = trunc_sat(total as f64 * leader_share) as f64 / 1e6
new_total = saturating_u64(max(total, 0) + amount) as f64 / 1e6
reject code 2 if equity < 1e-7, or new_total < 1e-15, or equity / new_total < 0.05
```

A missing leader record or an empty record map also gives code 2. The test at 0x395bd77 is
`0.05 > fraction`, so a fraction of exactly 0.05 passes. A vector with 5.25 of equity against a
new total of 105 passes.

### Share rewrite 0x395a2c0

```text
new_total = saturating_i64(old_total + delta)
denominator = new_total > 0 ? max(new_total, 0) as f64 / 1e6 : 0.0
old_usd = old_total as f64 / 1e6
temporary map: address -> share * old_usd, for every record
temporary[depositor] += delta as f64 / 1e6, inserted at 0.0 when missing
for each entry:
    denominator < 1e-15  -> share = 0.0
    equity < 1e-7        -> share = 0.0
    otherwise            -> share = equity / denominator
```

Three details are easy to get wrong.

1. When delta > 0 the function sums the vault equity again (0x395a326 onward), then drops it. The
   linear decode in `evidence.json` (`walks.recomputed_sum`) finds 0 stores of r15 in 178
   instructions, and one read that only feeds the sum. rcx is reloaded from the caller value at
   0x395a5a9 and r15 is overwritten at 0x395a66e. The `usd` vectors give the same output for r15 = 0
   and r15 = 5e9. The shares are always computed from the caller's `old_total`. The only remaining
   effect of that sum is a possible recorder call.
2. Existing records get only their share written (0x395a9e3 and 0x395abf9). The time fields change
   only in a default record, which is used when the entry is new.
3. After the drain, a walk over every stored record (113 instructions) has 0 memory stores and
   0 calls (`walks.post_drain_walk`).

The share map multiplication is at 0x3be61fc, inside the collect loop reached from 0x3316bf0.

### Records

`layout.tsv` gives one decoded access for each of 48 fields. A `user_states` record is 48 bytes.

| Offset | Width | Observation |
| --- | --- | --- |
| +0x00 | 8 | f64 share |
| +0x08 | 8 | u64 sum, saturating add with a recorder call at qtys/mod.rs:829 |
| +0x10 | 8 | i64 sum, saturating add with a recorder call at qtys/mod.rs:830 |
| +0x18 | 12 | time, written only when the record is created |
| +0x24 | 12 | time, rewritten by each deposit; read by 0x39597b0 |

0x39597b0 adds lockup_duration to record +0x24. For a missing record it builds a date from day
count 719163. The stored map node has 11 values of 48 bytes, the parent pointer at +0x210, 20-byte
keys at +0x218, the length at +0x2f6 and edges at +0x2f8.

### Equity helper 0x3955e80

```text
equity = saturating_i64(perp_value + (token_0_value + second_term) / 100)
```

`perp_value` is the first output qword of 0x37d79e0. `token_0_value` is the entry for key 0 in the
ledger returned by 0x371b3a0. `second_term` is a product divided by 1e14 from the address map at
context+0x10 +0x100. The `/ 100` sequence at 0x3956233 is evaluated as bytes in the `hundredth`
span. The product side of the second term is pinned but not evaluated.

### Lists

`address_lists.tsv` holds both lists, read from the `pcmpeqb` constants: 8 addresses each, with all
padding bytes checked as zero. List A lets a vault with a negative total accept deposits. List B
skips the leader share gate. Each list has other callers (`callers.tsv`), so these two uses do not
define them.

### Callers

`callers.tsv` is a byte census of `e8`, `e9` and `ff 15/25` sites landing on 11 path functions, 96
rows. 0x395b3a0 has 4 callers: the 3 transfer host copies and 0x395af60. 0x395a2c0 has 2:
0x395b3a0 and 0x395bdd0. 0x395af60 and 0x3959900 each have 3 callers, one per host copy. A byte
census may include immediates that look like calls. Each direct target had to be an exact
function start and each slot had to hold a relocation.

### Evaluation

The tool evaluates 7 call-free byte spans over 512 vectors each. It also evaluates the create body
from its entry to the deposit call and the modify body from its entry to its result, over 1024
vectors each. Everything is compared with plain formulas, and all 9 agree on every vector.

| Target | Vectors reached |
| --- | --- |
| Leader gate | 160 passes, 73 fraction rejects, 279 equity rejects, no `total<1e-15` reject |
| Create body | 69 deposit calls and codes 1, 3, 4, 5, 319, 323 |
| Modify body | 597 code 390 and codes 3, 4, 5, 319, 323 |

In the two bodies, these calls are replaced by named stubs: free, the user state lookup, the margin
summary and both ledger lookups. Modify vectors use one-node stand-in ledgers. `vectors.tsv` keeps 21
named span cases and `outcomes.tsv` keeps 24 named body cases.

### Reference comparison

| Reference text | Bytes |
| --- | --- |
| `version` u32, with version 2 as a child-vault gate | `VaultRelationship` tag, with the child set in the parent variant |
| version 1 and deposit-disable tests compare with `vault_address` | both compare with the leader |
| `apply_vault_deposit` has no leader share gate | gate 4 exists with code 2 and list B |
| `old_total` is the current total minus the deposit | `old_total` is the sum taken before the debit |
| `base_total` uses the recomputed total for positive deltas | the recomputed sum has no reader |
| every record gets `last_update_id` | existing records get only the share |
| receipt carries `share_fraction` | receipt carries amount / 1e6 |
| `VoteGlobalVaultModification` has manager, `max_distributable`, `is_cross_margin` fields | the 9 fields in `layout.tsv`, with none of those uses |

## Implementation and comparison

not yet implemented. No Rust was written. The formulas above are readings of the bytes, checked
over the listed vectors. They are not a claim of binary equivalence.

## Results and limitations

Passed: 216 pins, 48 layout rows, 13 named Vault fields, 16 list addresses, 11 Location records, 7
spans at 512 of 512, 2 bodies at 1024 of 1024 and two linear decodes.
`tests/test_vault_lifecycle_path.py` runs 24 tests. Its negative controls cover a wrong binary hash, a
flipped branch, changed code and limit immediates, a changed field offset, mutated 0.05, 0.1 and
1e-7 constants, addresses outside file-backed sections, an unknown encoding, an unmodelled call and
a serializer site that is not a key.

Limits:

- Deposit and rewrite were evaluated as spans, not as whole functions. The path between spans rests
  on the pins and on reading the code. Calls were not followed in any body.
- The create host gates are pinned, not evaluated.
- Inferred: the flag on 0x395b3a0 marks a creation deposit, from its two callers. The 12-byte times
  fit `chrono::NaiveDateTime`, and day count 719163 fits the Unix epoch.
- Inferred: context byte +0x8f2 uses the order `Local, Sandbox, Testnet, Mainnet` from a variant
  table, so 86400 seconds would be the Mainnet lockup. No read ties the table to this byte.
- Inferred: 0x3959900 is the vote action, from the 9-field match and from the reference label. Its
  single host path through 0x2355f40 was not walked.
- Unresolved: the two captured amounts in the create host, what field `s` means, why the recomputed
  sum and the post-drain walk remain, what lists A and B stand for, the names of record +0x08 and
  +0x10, and what `second_term` measures.
- Helpers 0x36f7560, 0x370a3d0 and 0x36ff4f0 are named by call position only.
- `0x3956320` is out of scope here. It has no call to 0x395a2c0, while 0x395b3a0 does. That is a
  reason to check any label that calls 0x3956320 the deposit body.

Next question: which callers read record +0x18, and does the withdraw body 0x395bdd0 use the same
pre-debit total when it calls 0x395a2c0?
