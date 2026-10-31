# RE-006: from one fill record to the rows, the flush, and the Trade and Fill JSON keys

This packet shows what a fill turns into after the match on node #94: one kind 6 row and two kind 8 rows per fill, one per side, carrying a two byte `trade_dir_override` of that side, and it names all 11 values of that byte (`Settlement` for halts, `LiquidatedMarket`, `BoleBackstopLiquidation` and so on), so a reconstruction can write the row writer, the kind 8 flush and the Trade and Fill records from tables, with each caller's override value taken from `call_sites.tsv`.

- Component ID: RE-006 (book state transitions), the output of a fill from the fill vector to the JSON keys
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are writers `0x26f4400`, `0x44714b0`, clones `0x256a5b0`, `0x256c7e0`, `0x487d630`, `0x4876b10`, `0x488a150`, kind 5 vectors `0x254f5c0`, `0x2550850`, `0x4847ed0`, `0x484c0f0`, leg helpers `0x24c3f00`, `0x24c40d0`, `0x47c3780`, serializers `0x47ee6e0`, `0x47ef7a0`, `0x49c9610`. Real bytes with no mutants, because another packet names the address: writers `0x4470be0` (#926), `0x26f4cd0` (#902, #977, #858), `0x4cd84f0` (#926, #212, #197), leg helper `0x47c39b0` (#537), clone loop `0x24bfe30` (#875), flush `0x24fc8a0` (#319, #650), sink `0x48547d0` (#851), builder `0x4a06dc0` (#941). Those packets hold caller rows or a byte binding; none states this behavior. Stubbed at the edge: field writers, row drop `0x47e0020`, Trade and Fill sinks `0x47edc30`, `0x47edfe0`, Fill builder `0x4c00c40`, price and size views `0x45a46e0`, `0x45a4ae0`, slots of `0x3728670`, `0x372e0a0`, `0x372faa0`, `0x371b3a0`, `0x372d970`, allocator, memcpy. Excluded: the bodies of those stubs, the insert and match that make the fill, what Fill builder `0x4c00c40` does with a row, and the second sink `0x48551e0`.

## Reproduce

From the repository root:

```
python3 tools/fill_row_output.py --out research/work-items/RE-006-fill-row-output-94
python3 -m unittest tests.test_fill_row_output
```

The tool takes about 240 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### Path map

| Step | Functions |
| --- | --- |
| Fill vector | from the insert result, or from a host that builds it |
| Row writer, fills of 0x228 bytes, rows of 0x268 bytes | `0x26f4400`, `0x4470be0`, `0x44714b0` |
| Row writer, fills of 0x238 bytes, rows of 0x278 bytes | `0x26f4cd0`, `0x4cd84f0` |
| Row flush, kind 8 arm | `0x24fc8a0` arm `0x24fcd01`, table `0x3e4a5c` |
| Row sink | `0x48547d0` from flush `0x432a990`; `0x23d9f20` and `0x4520f70` only drop the row |
| Trade JSON | `0x47ee6e0`, `side_info` row `0x47ef7a0` |
| Fill JSON | `0x49c9610` |
| Override text | wrapper `0x4865280`, field writer `0x4a8a4f0`, value `0x4c66c50`, tables `0x70c46c`, `0x70c498` |

`copies` holds size, SHA-256, argument form, helpers and flag table of each writer. The writers differ in argument form and helpers; `0x4470be0` and `0x44714b0` differ in one call target. `dispatch.row_sinks` lists each sink site.

### Rows of one call

Arguments: fill pointer and count, a 33 byte hash block (tag, then 32 bytes), a flag, a code dword, the row Vec. The 0x238 writers also take the oracle rows.

1. The fill vector is cloned. A clone may reorder: four clones turn tail `+0x00` price, `+0x08` coin into coin, then price; clone `0x4876b10` keeps its order.
2. Flag set: one kind 5 row with a Vec of all clean fills, written even for 0 fills.
3. For each fill, kind 6, kind 8 with side byte 0, kind 8 with side byte 1, in that order. Each kind 6 row is pushed before the reference word is read.

Legs go through a helper that turns tag dwords into clean words and leaves the bytes of an unset option out. `row_kind_5`, `row_kind_6`, `row_kind_8`, `leg_0xf8`, `leg_0x100` in `fields` hold the offsets.

Code dword: byte 0 and 1 go to side 0, byte 2 and 3 to side 1. Kind 6 has two flag bytes:

| Byte | Rule |
| --- | --- |
| first | 1 when byte 0 is in mask `0x7be` (1 to 5, 7 to 10), else `table[byte 2]`; the first 11 table bytes equal the mask, and larger values read on into other rodata |
| second | 1 when byte 0 and byte 2 are both 0 |

Reference word of kind 8: fill word (tail `+0x20`), unless it is 0. Then 0x228 fills take the price. 0x238 fills take word `+0x20` of oracle row `coin % 10000`, stride 0x60, and an index at or past the count panics at `l1/src/clearinghouse/oracle/oracle.rs:197` after the kind 6 row is already in the Vec (`locations`). A 0x238 fill whose first word is 2 stops the loop; 0x228 fills cannot, since their clone cleans the tag.

### The override byte

Key `trade_dir_override` at Trade `+0xe4` runs through `0x4865280`, `0x4a8a4f0`, then `0x4c66c50`, which reads one byte through table `0x70c46c`:

| Byte | Name |
| --- | --- |
| 0 | `Na` |
| 1 | `LiquidatedCross` |
| 2 | `LiquidatedIsolated` |
| 3 | `Settlement` |
| 4 | `AutoDeleveraging` |
| 5 | `NetChildVaultPositions` |
| 6 | `LiquidatedMarket` |
| 7 | `SpotDustConversion` |
| 8 | `BoleBackstopLiquidation` |
| 9 | `BolePartialLiquidation` |
| 10 | `OutcomeUserAction` |

Variant 10 reads the next byte through table `0x70c498`: 0 `SplitOutcome`, 1 `MergeOutcome`, 2 `NegateOutcome`, 3 `MergeQuestion`. This is why the code dword gives each side two bytes. Fixed values in `call_sites.tsv`, by byte patterns before each of the 38 direct calls:

| Code | Hosts |
| --- | --- |
| `0x30003` Settlement | `0x4cf0850`, `0x4cf0d10` (perp halt), `0x4d0fe80`, `0x4d10a80` |
| `0x50005` NetChildVaultPositions | `0x4cdb8a0`, `0x4cdbef0` |
| `0x60006` LiquidatedMarket | `0x4cff140`, `0x4cff8f0` |
| `0x80008` BoleBackstopLiquidation unless a register overrides it | `0x2765600`, `0x4d96ad0`, `0x4d98480` |
| 0, Na | plain order hosts and others, see the file |

Every other site computes the word; the file marks those `computed`, and they are not read here.

### Flush

`0x24fc8a0` takes the Vec, stops at head word 0xb, and dispatches on `kind - 2`, with heads 0 and 1 on index 7 (`dispatch.flush`). Kinds 5 and 6 pass with their fields. Kind 8 runs, in order:

1. coin at or past state `+0x200` panics; else token = state `+0x1f8` row `coin * 0x20`.
2. `0x3728670` on the token; when true, `0x372e0a0` with side and record.
3. When the price is not 0, `0x372faa0` with a rebuilt record whose `+0x1f0` is the price and `+0x1f8` the coin, the input order again.
4. `0x371b3a0` on the user of this side's leg, then a B-tree walk by token. Hit: value word at node `+0x70 + i * 0x18`. Miss: 0.
5. `0x372d970` on side and record.

The output row is the fill record moved down 8 bytes, so its head word is the leg 0 tag, 0 or 1, not 8. Then word 1 and the tree value at `+0x228`, `+0x230`, the reference word at `+0x238`, codes and side at `+0x240`, hash block at `+0x243` (`row_after_flush`). That is why sink index 6 serves heads 0 and 1.

### Sink

`0x48547d0` dispatches on the same head (`dispatch.sink`). Kinds 5, 6, 7, 9 only drop. Heads 0, 1 and 8:

| Object `+0x4e8` | Object `+0x420` | Row side equals row `+0x224` | Result |
| --- | --- | --- | --- |
| set | any | any | Fill through `0x4c00c40`, `0x47edfe0`, twap words from the leg of the row side |
| `i64::MIN` | set | yes | Trade through `0x47edc30` |
| `i64::MIN` | set | no | nothing |
| `i64::MIN` | `i64::MIN` | any | nothing |

So one fill gives two Fill records, one per side, or one Trade, from the side stored in the fill. Trade `+0xe4`, `+0xe5` take that row's two code bytes, and the hash is zero unless row tag bit 0 is set. `side_info` holds both legs. `start_pos` is leg `+0x08` as f64 over a power of ten by token byte `+0x49`, or 0.0 when the tag bit is clear, and for leg 0 that tag is the row head.

### JSON keys

`keys` in `evidence.json` lists every key with its offset as the real serializers ask for them. Trade, 8 keys: `coin +0x90`, `side +0xe6`, `time +0xd8`, `px +0xa8`, `sz +0xb0`, `hash +0xb8`, `trade_dir_override +0xe4`, `side_info +0x00`. `side_info`, 5 keys: `user +0x20`, `start_pos +0x10`, `oid +0x18`, `twap_id +0x00`, `cloid +0x34`. Fill, 22 keys with all gates open; 7 are gated: `builderFee` when `+0xe0` is not 0, `cloid` when byte `+0x102` is not 0, `liquidation` when byte `+0x85` is not 2, `feeTrialEscrow` when `+0xf0` is not 0, `builder` when byte `+0x113` is not 0, `deployerFee` when `+0xf8` is not 0, `priorityGas` when `+0x10` is not 0.

### Inferences

- Marked as inference: tail `+0x20` is a reference price, since its fallbacks are a price and an oracle row word. The tree value at flush step 4 is the balance Fill uses as `startPosition`: the tree key and user fit, and the Fill builder is not read.
- `0x4cf0850` being a perp halt comes from #212, and fits `Settlement`. The named hosts for 5, 6 and 8 fit their names; each name is proved only for the byte.
- The first flag byte is 1 for every override but `Na` and `LiquidatedMarket`. Its meaning is unknown.

### Unresolved

- Who reads kinds 5 and 6: the sink drops them, and the row scanner is not in this packet.
- Why object `+0x4e8` wins over `+0x420`; both look like optional output writers.
- What hosts with `computed` codes pass. `0x4cf43c4` builds the word from a register with `sbb`, `add 2`.
- The second sink `0x48551e0` and flushes other than `0x24fc8a0` are not run; #265 names `0x432a100` and `0x432a990`.

## Implementation and comparison

not yet implemented. The file carries a specification in Python only as a check of the bytes.

## Results and limitations

| Cases | 615 |
| Mismatches | 0 |
| Instructions stepped | 696,834 |
| Stepped / total: first row writer, 0x228 fills | 417 / 453 |
| Stepped / total: third row writer, 0x228 fills | 411 / 446 |
| Stepped / total: first clone | 53 / 61 |
| Stepped / total: perp first clone | 53 / 61 |
| Stepped / total: spot second clone | 100 / 108 |
| Stepped / total: spot third clone, keeps the output order | 80 / 88 |
| Stepped / total: perp second clone | 101 / 108 |
| Stepped / total: first kind 5 vector | 450 / 475 |
| Stepped / total: perp first kind 5 vector | 431 / 453 |
| Stepped / total: spot second kind 5 vector | 86 / 92 |
| Stepped / total: perp second kind 5 vector | 86 / 92 |
| Stepped / total: first leg helper, 0xf8 | 105 / 105 |
| Stepped / total: perp first leg helper, 0x100 | 102 / 102 |
| Stepped / total: perp second leg helper, 0x100 | 102 / 102 |
| Stepped / total: Trade serializer | 86 / 96 |
| Stepped / total: side_info serializer | 68 / 78 |
| Stepped / total: Fill serializer | 239 / 249 |
| Stepped / total: second row writer, named in #926, run with no mutants | 411 / 446 |
| Stepped / total: perp first row writer, caller row in #902, #977, #858, run with no mutants | 448 / 486 |
| Stepped / total: perp second row writer, named in #926, #212, #197, run with no mutants | 455 / 492 |
| Stepped / total: spot second leg helper, row in #537, run with no mutants | 105 / 105 |
| Stepped / total: first clone loop, row in #875, run with no mutants | 442 / 446 |
| Stepped / total: row flush, row in #319, #650, run with no mutants | 610 / 865 |
| Stepped / total: row sink, bound as bytes in #851, run with no mutants | 222 / 491 |
| Stepped / total: side_info builder, run with no mutants | 77 / 83 |
| Mutants killed / survived / unreached | 993 / 101 / 65 |

Each surviving row has its reason in `mutations.tsv`. Most flip the low bit of a memcpy or stack copy length, which moves one byte of padding or a block the next copy rewrites. Others are stores repeated on the same stack row, the dead loop stop of 0x228 fills, and capacity limits of the clones.

Limits: every case uses fake state. The B-tree in the flush has one or two levels. Fill vectors reach 3 fills. `0x4cd84f0`, `0x4470be0`, `0x26f4cd0` run with no mutants, as stated above, and the second flush and the Fill builder are not run. A mutant counts as killed only if a run differs in a row field, a kept allocation, a byte past the last row, a key, the edge log or a panic.
