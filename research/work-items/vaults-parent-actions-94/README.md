# vaults: node #94 leader and parent actions: vaultModify, vaultDistribute host and NetChildVaultPositions

This packet shows that NetChildVaultPositions moves every listed child vault to one equal size per
asset, with the first listed child as the other side of each fill at the oracle price, and it pins
the vaultModify and vaultDistribute host arithmetic, so these three actions can now be written from
the bytes instead of from the reference's candidate-scan description.

- Component ID: vaults
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository 1f8c67c; reference `references/can1357-hl` used as a label source only
- Claim status: observation for pins, layouts and evaluated results; inference where marked; unresolved items are listed at the end
- Scope included: 0x22c5fd0, 0x26f6a80, 0x1e60020, 0x26f6110, 0x27e8cb0, 0x26f6c30, 0x3707c20, 0x3c188f0
- Scope excluded: the distribution body 0x3956320 (open PR #635), the wire asset classifier 0x3c0cc70 (open PR #650), the margin test 0x3711ba0, the fill apply 0x3710a70, the fill row writer 0x26f4cd0, the post step 0x24fb610, the vaultTransfer pair

## Reproduce

From the repository root, Python 3 standard library only, no external programs:

```sh
python3 tools/vault_parent_actions.py --out research/work-items/vaults-parent-actions-94
python3 -m unittest tests.test_vault_parent_actions
```

The tool checks the binary SHA-256, reads ELF bytes, and imports `tools/elf_index.py` and
`tools/fde_extents.py` for sections and FDEs. It never runs the binary. It writes evidence.json,
functions.tsv, stubs.tsv, callers.tsv, pins.tsv, layout.tsv, locations.tsv, cases.tsv and
outcomes.tsv. All contents are deterministic.

## Evidence

Addresses are ELF virtual addresses. Function extents are FDE ranges (`functions.tsv`), 8 functions
and 10,715 bytes in all. Instruction text in `pins.tsv` comes from the small decoder inside the tool,
not from objdump, and each of the 148 rows is compared with a frozen expected string. Unknown
encodings raise an error. `layout.tsv` gives 60 field offsets, each tied to one decoded access.

### Entry points

`callers.tsv` is a byte census of `e8` and `ff 15/25` sites that land on the 8 functions. All three
wrappers are called only from the dispatcher 0x2759240, at the indexes RE-010 mapped. Each body has
one caller. The scan 0x3707c20 has 3 slot callers: the core 0x26f6f9f and two sites outside this
path (0x4cdbc0f, 0x4cdc25f).

### vaultModify

The action is two flag bytes then the address at +0x02 (`struct VaultModifyAction with 3 elements`).

| Step | Test | Result |
| --- | --- | --- |
| 1 | vault key missing | tag 14, code 7, address echoed at result +0x0a |
| 2 | caller != leader +0x98 | tag 14, code 17 |
| 3 | action address != vault_user +0x84 | tag 13, code 390, nothing stored |
| 4 | byte 0 != 2 | store allow_deposits +0xad |
| 5 | byte 1 != 2 | store always_close_on_withdraw +0xae |

Code 390 is loaded before the compare in step 3 (0x26f6bd1), so a mismatch reports success. Whether
a stored vault can have a map key different from vault_user was not searched.

### vaultDistribute host

The action is usd at +0x00 and the address at +0x08. `is_closed` is tested before the leader.

| Step | Test | Result |
| --- | --- | --- |
| 1 | usd >= 0x0ccccccccccccccc | code 319 with usd |
| 2 | vault key missing | code 7 with the address |
| 3 | is_closed +0xac | code 8 |
| 4 | caller != leader | code 17 |
| 5 | usd != 0 and usd > available(vault address) | code 18 |
| 6 | call the body through slot 0x57748b8, flag = usd != 0 | other codes are copied out |

With usd == 0 the host reads no balance. The body returns a map of address to i64 change. The host
then runs, for each entry in key order:

```text
r = trunc_sat(change as f64 * clearinghouse[0]+0x2a0)    non-finite product gives 0
r == i64::MIN                                            panic, core num mod.rs:320
r = clamp(r, -0x147ae147ae147ae, 0x147ae147ae147ae)
step = r / 10000, truncating toward zero
address == vault: account +0x10 += step, saturating
always:           account +0x18 += step, saturating
event tag 0x8000000000000006, amount abs(r) / 1e6, users [address], vault address
```

The f64 cast truncates. The amount in the event is the scaled, clamped value, not the raw change.

### NetChildVaultPositions

The action is a `Vec<[u8; 20]>` of children at +0x00 and a `BTreeSet<u32>` of assets at +0x18. The
set node has u32 keys at +0x08, the parent index at +0x34, the length at +0x36 and edges at +0x38.
`struct NetChildVaultPositionsAction with 2 elements` is in the binary.

Host 0x27e8cb0, in this order:

| Step | Test | Result |
| --- | --- | --- |
| 1 | asset count >= 10001 | code 323, payload points at action +0x18 |
| 2 | for each asset: classifier code != 390 | code copied out |
| 3 | classifier kind == 1 | code 350 |
| 4 | asset / 10000 >= clearinghouse count | panic, unwrap of Err(321), clearinghouses.rs:11:29 |
| 5 | clearinghouse[asset / 10000]+0x230 != 3 | code 97 with the asset |
| 6 | child count >= 10001 | code 323, payload points at the action |

Core 0x26f6c30 uses the caller address as the vault key:

| Step | Test | Result |
| --- | --- | --- |
| 1 | caller is not a vault key | code 7 with the address |
| 2 | relationship tag < 2 | code 24 |
| 3 | any child outside the vault child set | code 27 |

The core has no leader compare. The list and set go to the scan through slot 0x57748c0, with
clearinghouse 0, the chain byte +0x8f2, the exchange and exchange +0x5d0.

Scan 0x3707c20:

```text
n <= 1: return an empty map
weight = 1.0 / n as f64
for asset in the u64 set, ascending:
    total = saturating sum of position size over every child, first included
    target = trunc_sat(total as f64 * weight)
    px = oracle row[asset % 10000]+0x20
    for child at index 1..n in list order:
        chain byte 2: perp_meta row[asset % 10000]+0x28 == 2 skips this child
        delta = saturating(size(child) - target)
        delta == 0: skip
        first = children[0]
        delta > 0: first side = first, second side = child, side byte 1
        delta < 0: first side = child, second side = first, side byte 0
        take two ids from exchange +0x38, saturating
        size = abs(delta), notional = px * size
        notional overflows u64 or >= i64::MAX: skip
        margin test of both sides, bit 0 and bit 8 of the result must be set, else skip
        apply the fill now through slot 0x5774868
        push the 0x238-byte fill on the Vec for this asset
```

Four details matter for a rewrite.

1. The first child is never adjusted on its own. It absorbs every other side and ends with the rest
   of the total, so truncation leaves the odd units there (`cases.tsv`: a total of 301 across 3
   children gives a target of 100).
2. Ids are taken before the notional and margin tests, so a skipped child still spends two ids.
3. A refused child is not an error. The action returns code 390 with partial netting.
4. Fills apply during the scan. A child that appears twice in the list reads its updated size at
   the second position, while the total and target stay as computed at the start of the asset.

The closure 0x3c188f0 always writes 1 in the first slot, so the tag 2 skip at 0x37086f8 is not
reached from this closure.

After the scan the core calls 0x26f4cd0 once per asset with non-empty fills (flag 0x50005 and the
one-byte tag plus the 32-byte hash), then 0x24fb610 once, also when no fill happened. Exchange +0 == 1
selects a real hash from 0x3987cb0, otherwise 32 zero bytes.

`locations.tsv` holds 10 Location records. The oracle row bound is clearinghouse/oracle/oracle.rs:197:18
and the chain byte 2 test is perp_meta.rs:194:38. That is the reason for the names `oracle row` and
`perp_meta row`.

### Evaluation

The tool runs each body in Python over the real instruction bytes and compares the result with a
plain model. vaultModify runs both functions over 512 vectors. vaultDistribute runs its two functions
over 512 vectors with the body as a stub. NetChildVaultPositions runs the wrapper, core, scan and
closure over 256 vectors, 1280 in all, with 36 distinct outcomes in `outcomes.tsv` and
0 disagreements. `cases.tsv` has 19 named scenarios.

`stubs.tsv` lists the 25 replaced calls with their FDE extents. Fixtures build real B-tree nodes for
the vault map, child set, asset set and position maps, and a real SwissTable group for the user table.
The SipHash rounds at 0x3707f09 run for real. The absorb stub leaves the state at zero, so every key
hashes to the constant in evidence.json, and the group compare picks the key. Caller-saved registers
are overwritten after each stub.

### Reference comparison

| Reference text | Bytes |
| --- | --- |
| `assets: Vec<u32>`, capacity over 10000 rejected | `BTreeSet<u32>`, count >= 10001 gives 323; the child Vec has the same limit, tested after the assets |
| dex lookup miss returns status 321 | panic, unwrap of Err(321) |
| scan for liquidation-style candidate rows | equal-size sweep, first child as the other side |
| funding, position and storage update per candidate | fill apply in the scan, row writer once per asset, post step once |
| empty child list is a no-op | any list of 0 or 1 children |
| version gate | `VaultRelationship` tag >= 2 |
| vaultModify: leader check, then store | a vault_user compare follows, and a mismatch reports success with no store |
| distribute: `.round()` on the scaled amount | truncating cast |
| both account totals change for every user | +0x18 for every address, +0x10 only for the vault address |
| scaled amount added as is | scaled amount / 10000 |
| event carries `user_ledger_change` as i64 | f64 abs(scaled) / 1e6, plus a one-address user Vec |
| usd == 0 compares total with balance in the helper | the host reads no balance for usd == 0; that test would be in the body |

## Implementation and comparison

not yet implemented. No Rust was written. The formulas above are readings of the bytes, checked over
the listed vectors. They are not a claim of binary equivalence.

## Results and limitations

Passed: 148 pins, 60 layout rows, 8 functions, 25 stubs, 10 Location records, 1280 vectors with
0 disagreements and 19 named scenarios. `tests/test_vault_parent_actions.py` runs 42 tests: 7 positive,
8 negative controls (wrong binary hash, address outside file-backed sections, changed pin byte,
changed layout operand, unknown encoding, unmodelled call, non-FDE start, generated file drift) and
27 one-edit binary mutants, each of which the models or fixed expectations catch.

Limits:

- Stubs are assumptions about interfaces. Stub bodies, and the margin rule in particular, were not read.
  The stub for 0x5774868 moves only the two sizes, which is enough for the size reads in this path.
- Grid vectors use up to 7 children and up to 3 assets. Height 1 B-trees appear in the 14-vault
  vaultModify vectors and in one 13-asset named case; greater heights and multi-group SwissTable
  probing were not evaluated.
- The i64 saturation arms of the size sum and of size minus target run only in two named cases.
- Inferred: `+0x20` of an oracle row is a price, from its Location and its use as `px * size`.
- Inferred: the first side is the buyer. It gets the child when the child is below the target.
- Inferred: chain byte 2 is Testnet, from the variant order in the earlier vault work; no read ties
  the table to this byte.
- Unresolved: what clearinghouse +0x2a0 measures, what account +0x10 and +0x18 mean, what perp_meta
  row +0x28 value 2 means, and how the map key can differ from vault_user.

Next question: which actions reach the scan through 0x4cdbc0f and 0x4cdc25f, and do they pass the
same chain byte and child list?
