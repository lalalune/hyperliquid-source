# fees: who may name a perp dex fee recipient and a token deployer fee share in node #94

This packet shows that a dex fee recipient is an optional override at dex meta `+0x9d`/`+0x9e` that only the deployer or a sub-deployer holding kind 3 can set, and only to an address with a row in a dex table or in the map behind `0x3721c10`, not in the map at exchange `+0x8d0` (vaults, by inference), with abstraction off, and that a token deployer fee share can only go down, apart from one first set of a legacy token, so a reconstruction can now write both admission rules and the kind table of every perp deploy variant.

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes who controls where the deployer part of a fee goes, the rollover stays open).
- Target release and full SHA-256: hl-node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions and evaluated outcomes; inference where marked; unresolved items are listed at the end.
- Scope included: the `setFeeRecipient` path (variant 5) from the entry of `0x273e080`, `0x4d50130`, `0x4d55b50` to its end; deployer gate `0x3719030`; map search `0x284bc20`, `0x4927a10`; abstraction test `0x2745eb0`, `0x4d5fdc0`, `0x4d5fe60`; share setter `0x27512f0`, `0x4d75ad0`, `0x4d75a00`; the share arm at `0x23e8066`, `0x4ad7c06`, `0x4ad8536`; the variant and kind tables. Scope excluded: the bodies of the other 15 variants, the checks before the share arm in `0x23e7d10`, the two name lookups, `0x3721c10`, the row get, the text parser, the credit `0x37067b0` (pinned only), node #115.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/fees_deployer_recipient.py --out research/work-items/fees-deployer-recipient-94
python3 -m unittest tests.test_fees_deployer_recipient
(cd research/work-items/fees-deployer-recipient-94 && sha256sum -c MANIFEST.sha256)
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x273fbda --stop-address=0x2740180 artifacts/node/94/hl-node
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first and fails on any other file. It starts no external program, so no binutils version can change its output. Sections and FDEs come from `tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions are interpreted in Python. A full run takes about 90 seconds and writes `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv`, `reference-diff.tsv`, `variants.tsv` and `recipient-sites.tsv`.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame`, and whole functions decode to their FDE end. A path through an action has no FDE of its own: the tool walks both ways of each branch from the entry, takes entry 5 of each jump table, and ends at the drop of the action (`0f b6 45 00`) or after the outer tag store.

### Map of the path

| Step | First copy | Result |
|---|---|---|
| name length | `0x273e589` | over 100 bytes: tag `0x143`, pointer to the name at out `+0x10` |
| dex by name | slot `0x5774708` -> `0x3332270` | error forwarded, 0x60 bytes |
| status byte, row `+0x230` | `0x273ef5c` | not 0 or 3: tag `0x162` |
| gate, kind 3 | slot `0x5774bb8` -> `0x3719030` | tag `0xe4` or `0xe3` |
| known address | `0x273fbda`, `0x274007a` | none: tag `0x163` |
| not in map exchange `+0x8d0` | `0x284bc20` | present: tag `0x163` |
| abstraction off | `0x2745eb0` | tag `0xe0`, text below |
| dex by name again | slot `0x5773eb8` -> `0x3332380` | error forwarded |
| free the name, write | `0x27413d0` | meta `+0x9d = 1`, `+0x9e..+0xb2 =` address |

### Rule

```text
set_fee_recipient(sender, dex_name, a):
  len(dex_name) > 100              -> 0x143
  row = lookup(dex_name)           -> forwarded error
  row.status not in (0, 3)         -> 0x162
  gate(row, kind 3, sender)        -> 0xe4
  a has an item in table row +0xf8 of a dex in the list at exchange +0x5c0, stride 0x2f0, or known(a) is true
                                   else 0x163
  a in map exchange +0x8d0         -> 0x163
  m = user row byte +0x3c:  m > 3 needs byte exchange +0x5b0 == 1
                            m in (2, 3) needs byte exchange +0x5b1 != 0
                            else 0xe0 "User must have abstractions disabled"
  row = lookup(dex_name) again     -> forwarded error
  row.meta[+0x9d] = 1;  row.meta[+0x9e..+0xb2] = a
```

The table walk stops at the first dex that holds `a`, skips a dex whose item count at `+0x110` is 0, and then skips `0x3721c10`. The name is freed on every outcome from the known-address step on. In the shifted copy `0x4d55b50` the dex list and the map are at `+0xa80`, while `+0x80`, `+0x5b0` and `+0x5b1` are not shifted.

### Gate `0x3719030`

`gate(row, kind, sender)` returns a tag at out `+0`:

```text
row.status == 3:  kind == 0xe ? 0xe3 : 0xe4
sender == meta +0x74:  0x186
kind == 0xe:  0xe3
sender in set of kind in the tree at meta +0x48:  0x186
else:  0xe4
```

The tree at meta `+0x48`, height `+0x50`, has byte keys at node `+0x114`, length u16 `+0x112`, children `+0x120`, and 0x18-byte values at `+8` (root, height, length of an address set with keys at `+8` stride 20, length `+0xe6`, children `+0xe8`). So a sub-deployer right is per kind. `0xe4`: `Invalid perp deployer or sub-deployer`. `0xe3`: `Invalid perp deployer`.

`variants.tsv` lists all 16 variants with their dispatch, kind and arm, read from the tables at `0x3ed800`, `0x3ed840`, `0x3ed880`. Kinds are 0..13 in the order of the 14-name string, except `setSubDeployers`, which passes `0xe`, so a sub-deployer can never run it. The names are text from `.rodata` (`evidence.json`, `names`); their link to a variant number is by order, checked at 3 points: variant 5 reads an address in `setFeeRecipient`, variant 12 is the fee scale arm of `fees-fee-scale-94`, variant 13 is the growth mode arm.

### The two sets

`0x284bc20` and `0x4927a10` search a B-tree with 20-byte keys at node `+0x798`, length `+0x876`, children `+0x878`, 0xb0-byte values at `+0`, and return the value pointer or 0. The caller only tests for 0. `0x3721c10` is a stub here, called with exchange `+0x80`: it tests a table at exchange `+0x318`.

### Option word

`recipient-sites.tsv` is a byte census of `test` or `cmp` of byte `+0x9d` with 1 and stores of 1: 14 rows in 14 functions, including the 3 stores of this path. The site is the opcode byte, so a REX prefix sits one byte before it. Pins in `evidence.json`:

- `0x233b56e..0x233b592` in the serializer: key `fee_recipient` before `cmp [r14+0x9d], 1`, address at `+0x9e`.
- `0x233b4ec..0x233b514`: key `oracle_updater` for the option at `+0x88`.
- `0x3706807..0x3706819` in the credit `0x37067b0`: `+0x74` unless bit 0 of `+0x9d` is set, then `+0x9e`.
- `0x2768387`: the abstraction guard reads the same option.

### Share setter

`0x27512f0(out, exchange, token, share)`, with copies `0x4d75ad0` and `0x4d75a00`. The last one reads the network byte at `+0x1372`, the others at `+0x8f2`. The token row is `[exchange+0x210] + token * 0xe8`, count `+0x218`, value `+0xa8`.

```text
token >= count                  -> panic, Location l1/src/spot_meta.rs:119:37
share > 100000                  -> 0xdf "deployer trading fee share cannot be more than 100%"
token <= 0xc3 and byte == 3:
    old == 0                    -> write
    old <= share                -> 0xdf "deployer trading fee share cannot increase"
    share != 0                  -> write
    else                        -> 0xdf "cannot reset legacy token fee share"
old <= share                    -> 0xdf "deployer trading fee share cannot increase"
write
```

So outside the legacy rule a share never rises and an equal value is refused, which means a token with share 0 stays 0. A legacy token with a stored 0 may be set once to any value up to 100000, and a stored share can drop but never to 0.

The arm at `0x23e8066` reads token at action `+0x20`, tests it against the count (`0xea`, token at out `+0x10`), tests text length at `+0x18` (over 100: `0x143`), calls slot `0x5773168` -> `0x3364cd0` on the text at `+0x10`, and calls the setter. The value is text, not a number, at this layer.

## Implementation and comparison

Rust: not yet implemented. Comparison is between the decoded instructions, interpreted in Python, and a separate closed-form model in the tool.

- 6665 vectors, 0 mismatches. Input records fault on unset bytes where they matter, and exchange, dex rows, meta rows, action, name and token rows are compared after each run, so a stray write fails.
- Hash tables use the real group layout with clashing control bytes, tombstones and probes over several groups. B-trees use the real node layouts up to height 2.
- 709 byte mutants over `0x273e080`, the gate, both searches, all abstraction tests, all setters and all share arms: 665 killed, 44 equivalent with reasons in `mutations.tsv` and `evidence.json`, 0 unclassified. The other 2 action copies run every vector unmutated.
- 49 unit tests pass, with negative controls for the digest, a corrupted binary, a range outside any FDE, a path that reaches a return, a missing jump table, pins, status tags, the write offset, the kind byte, the cap and the legacy bound.

## Results and limitations

- Instructions executed: 1359 of 1590 on the 6 paths, 500 of 511 in whole functions. The rest are padding and the ranges in `evidence.json` `unexecuted`: allocator failure, the asset name list that is empty for this variant, status 3 after a passed gate, and a second name length test that the first test makes dead.
- `0x3332270`, `0x3332380`, `0x3721c10`, the row get, `0x399c7a0` and `0x3364cd0` are stubs that check their arguments, so name lookup, the hash and the text parser are outside this result.
- Byte `+0x8f2 == 3` as mainnet is an inference from the testnet-only gate `0x22ce180` (tag `0x8d`). Exchange `+0x8d0` as the vault map is an inference: `0x2768170` returns tag `0x15`, `Vault may not perform this action.`, for a sender found in the same tree, read by hand, not evaluated here. The checks before the share arm in `0x23e7d10` are not evaluated, so deployer ownership of the token is not shown here.
- No state was read: no real recipient or share is claimed. #115 is not checked. `reference-diff.tsv` lists 7 rows.

Next question: what writes dex `+0x230`, whose state table sits at `0x3ed900` in the same action (byte set to 1 at `0x274111c`)?
