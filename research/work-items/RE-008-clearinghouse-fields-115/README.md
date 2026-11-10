# RE-008: node #115 Clearinghouse and PerpMeta field tables (stage 104)

- Component ID: abci. Question: #6207 showed that Locus `cls` holds 0x510-byte clearinghouse elements, and the stage 103 PR named element `+0x58` as `meta.collateralToken`. This packet names every field the Clearinghouse serializer writes, with its matcher index and element offset, and the fields of `meta` (PerpMeta).
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #6207 and the stage 103 PR; it does not depend on their files.
- Claim status: names, lengths, offsets, matcher index bytes and call targets are observations from bytes. Reading the offsets as struct field offsets is an inference from the serializer shape. The binary was not executed.

## Reproduce

```
python3 tools/clearinghouse_fields_115.py --check
python3 -m unittest tests.test_clearinghouse_fields_115
```

The tool reads the ELF only. The three `*.objdump.txt` files (GNU objdump 2.42) are for review; the tool does not read them.

## Clearinghouse (serializer `0x4482170`, matcher `0x445dd80`)

Each name is loaded with `lea rsi,[rip+…]` and `mov edx, len`; the value pointer comes from `rbx` (the element) plus the offset. Four names are loaded inside one-field helpers (`0x44f46e0`, `0x44f4900`, `0x44f40c0`, `0x44f3d00`). The matcher stores the index byte (`mov cl, imm`); 0x13 means unknown (`0x445e0da`). The index equals the serialization position for all 19 fields.

| Index | Field | Offset |
|---|---|---|
| 0 | meta | +0x0 |
| 1 | user_states | +0x60 |
| 2 | oracle | +0x148 |
| 3 | total_net_deposit | +0x4a8 |
| 4 | total_non_bridge_deposit | +0x4b0 |
| 5 | perform_auto_deleveraging | +0x508 |
| 6 | adl_shortfall_remaining | +0x4b8 |
| 7 | bridge2_withdraw_fee | +0x4c0 |
| 8 | daily_exchange_scaled_and_raw_vlms | +0x2f8 |
| 9 | halted_assets | +0x4c8 |
| 10 | override_max_signed_distances_from_oracle | +0x318 |
| 11 | max_withdraw_leverage | +0x509 |
| 12 | last_set_global_time | +0x4f0 |
| 13 | lnsgt | +0x4fc |
| 14 | usdc_ntl_scale | +0x4e0 |
| 15 | isolated_external | +0x338 |
| 16 | isolated_oracle | +0x358 |
| 17 | moh | +0x378 |
| 18 | znfn | +0x4e8 |

## PerpMeta (`meta`, serializer `0x3c40400`, called at `0x4482213` with `rdi = rbx`)

| Field | Offset |
|---|---|
| universe | +0x0 |
| collateralTokenName | +0x18 |
| marginTableIdToMarginTable | +0x30 |
| pdi | +0x50 |
| collateralToken | +0x58 |

## Cross-checks with earlier packets

- #6207's per-element list at `+0x8` with length at `+0x10` lies in `meta.universe` (a Vec: pointer `+0x8`, length `+0x10`). Inference: the 0x20-byte items it indexes are universe entries.
- #6207's index check at `+0x50` is `meta.pdi`; the stage 103 field `+0x58` is `meta.collateralToken`.
- #6213's move_token leg balance at `+0x4a8` is `total_net_deposit`.

## Results and limitations

- 19 Clearinghouse fields and 5 PerpMeta fields are bound by name, index (Clearinghouse) and offset. 10 tests pass; 8 mutate one byte and expect rejection.
- Limits: field types and value layouts are not decoded; the PerpMeta field matcher (indices) is not mapped; byte-sized fields (`perform_auto_deleveraging` `+0x508`, `max_withdraw_leverage` `+0x509`) are offsets only. No gate changes.
