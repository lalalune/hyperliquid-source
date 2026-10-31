# bridge: the wire form of EthEventId and of the two deposit vote actions in node #94

This packet gives `EthEventId`, the key of every deposit and validator set vote map, its real shape, so a reconstruction can build the key type and both deposit vote actions from the bytes: five fields `b`, `t`, `e`, `i`, `h` in 64 bytes, not the two fields the reference infers, where `e` is a six-variant `EventType` string and `h` a hex string, and the same action travels flat as `VoteEthDepositAction` and nested as `l1ValidatorVoteBridgeDeposit`.

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`; first task "Map message hashes, nonce lifecycle"; only the identity and wire form of a deposit vote are claimed here)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for bytes, field order, offsets, output bytes, error text and rodata text; inference for the meaning of each field and for which arm each action feeds; unresolved items are under limits
- Scope included and excluded: included are the 23 functions in `path.tsv`, run whole on fixtures, and 24 compiled copies run against the same rules (`copies.tsv`). Excluded are the `Action` enum dispatchers that call them, the msgpack reader that builds a `Content` value, what a vote does with the key (`bridge-deposit-votes-94`), and the validator set update actions that also carry this key.

## Reproduce

```
python3 tools/bridge_eth_event_wire.py --out research/work-items/bridge-eth-event-wire-94
python3 -m unittest tests.test_bridge_eth_event_wire
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes of each function from its entry, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes about 5 minutes with four worker processes.

## Evidence

Addresses are virtual addresses. Reached instruction rows are in `function-rows.tsv`. Rows quoted below are bound in `key-rows.tsv`, so a moved row fails the run.

### The key

| Field | Offset | Type on the wire | Bound by |
|---|---|---|---|
| `b` | `+0` | unsigned integer | `0x374c243` |
| `t` | `+8` | unsigned integer | `0x374c295` |
| `e` | byte `+0x38` | name string | `0x374c2e8`, table `0x5974b0` |
| `i` | `+0x10` | unsigned integer | `0x374c3de` |
| `h` | `+0x18`, 32 bytes | `0x` + 64 lower hex digits, as a string | `0x374c440`, formatter slot `0x5773120` |

The key is `0x40` bytes and the 7 bytes after `e` are padding. The wire order is the compare order pinned in `bridge-deposit-votes-94` (`b`, `t`, `e`, `i`, `h`), which is what a derived `Ord` on this field order gives. The struct name and field letters are in rodata (`texts.tsv`): "struct EthEventId with 5 elements" appears in the error of a short sequence.

### EventType

| Index | Name | Text |
|---|---|---|
| 0 | `Deposit` | `0x597ec0` |
| 1 | `InvalidatedWithdrawal` | `0x597ec7` |
| 2 | `RequestedWithdrawal` | `0x597edc` |
| 3 | `FinalizedWithdrawal` | `0x597eef` |
| 4 | `FinalizedValidatorSetUpdate` | `0x597f02` |
| 5 | `RequestedValidatorSetUpdateEvent` | `0x20c960` |

The last name has the suffix `Event`, the others do not. Value 6 is the niche for "no key", which is the loop end pinned in `bridge-retention-prune-94` and the "not seen yet" mark at `0x3b67d1f`. `events.tsv` binds names and table rows.

### Output forms

The action is `usd` at `+0`, the key at `+8` and `user` at `+0x48`. It has three writers (`wire-samples.tsv` has full bytes for every function):

| Writer | Functions | Form |
|---|---|---|
| msgpack a | `0x374c200`, `0x3b67480`, `0x3b66e90`, `0x3282d50` | serializer flag `+0x1b` picks map or array |
| msgpack b | `0x374bf80`, `0x3b67740`, `0x3b678e0`, `0x3282ee0` | flag `+0xb`, same bytes as a on every case |
| JSON | `0x374bda0`, `0x3b66b70`, `0x3b671b0`, `0x3283030`, `0x374b830` | pretty printer with the caller's indent |

The head byte is `0x85` or `0x95` for the key (`0x374c227`), `0x83` or `0x93` for the action, `0x84` or `0x94` for the flat form and `0x82` or `0x92` for the nested form. Integers take the smallest msgpack width. The array form drops keys only: a compact flat action starts with its tag string.

```
flat    {type: "VoteEthDepositAction", user, usd, ethId}
nested  {type: "l1ValidatorVoteBridgeDeposit", action: {user, usd, ethId}}
```

Both tags are taken from the callers: the flat tag at `0x334da88`, the nested tag at `0x334d0a0`.

### Input forms

`0x3b67ad0` and `0x3b68460` read a buffered serde `Content` value, tag `0x14` sequence, `0x15` map, `0x13` newtype, and `0x16` the empty mark. They differ only in the error type: the first boxes a `serde_json` error, the second returns an inline error with text at `+0x10`. One text differs: unit prints as `null` in the first and `unit value` in the second (`action_from_content_json_act_not_struct_unit`, the same name with `rmp`).

Rules, each with cases in `scenarios.tsv`:

| Rule | Example case |
|---|---|
| `EthEventId` ignores an unknown key; the action and the nested struct refuse it | `event_id_from_content_json_id_extra_key`, `action_from_content_json_act_extra_key` |
| Sequence form works at each level; too short names the struct, too long gives "invalid length 6, expected 5 elements in sequence" | `event_id_from_content_json_id_seq_long` |
| Missing fields are named in field order; a duplicate is refused before its value is read | `subset_*`, `dup_*` |
| A key may be text, bytes, or a `u8` or `u64` index; other integer widths are refused | `int_keys`, `u16_key` |
| `e` is a string, or a one-key map with a unit value, where the key may be a name or an index below 6; a bare integer is refused | `event_map_*`, `event_int` |
| `b`, `t`, `i`, `usd` take any integer width that is not negative, and no text | `b_u8`, `b_i8_minus`, `b_text` |
| `usd` takes one newtype layer, `user` any number, `h` none | `usd_newtype_newtype`, `user_newtype_newtype`, `h_newtype` |
| Hex: optional lower-case `0x`, either digit case, length tested before digits; raw bytes of the exact size pass | `h_cap_prefix`, `h_upper`, `h_odd_bad_head`, `h_bytes` |
| A bad hex digit is named by its byte as a Latin-1 character, at an offset that counts the prefix | `h_bad_nonascii`, `h_bad_bare` |
| The nested struct is named `L1ValidatorVoteBridgeDepositAction` in errors and has one field | `nested_from_content_json_nest_seq_empty` |

### Copies

The binary holds this path several times. `copies.tsv` lists 20 serializer copies and 4 reader copies that each match the same rules, with the reader copies running every reader case of their primary. `0x4c42b50` is 174 bytes longer than `0x3b68460` and matches on every case.

### Reference differences

| Reference `l1/bridge2.rs` | Bytes |
|---|---|
| `EthEventId { block_number, log_index }`, "member names are inferred" | five fields, `0x40` bytes, an event type and a 32-byte hash |

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the machine, that predicts every output byte, every decoded field and every error text.

## Results and limitations

- 23 functions, 4981 reached rows. 2913 named cases and 200 generated cases: 0 mismatches. Every allocation is checked: an accepted input leaves nothing live, an error leaves only the error, and each free carries the right size.
- 2023 byte edits on reached rows: 1656 killed, 367 survived (`mutations.tsv`). A survivor has a class label only and is not proved equal; many surviving branches are writer capacity tests, where growing early can write the same bytes. Each edit runs at most 10 cases that reach it, half the cheapest and half spread over the rest.
- 3418 bytes of the 23 bodies are not reached: landing pads, allocation failure and rows for writer errors. There is no list of those rows, because the tool decodes only from reached rows.
- The rule list was written after reading the matrix output, so a match shows it is complete on these cases and is not an independent prediction.
- The `Content` value is built by the fixture from the serde tag layout, not by the real msgpack reader. Float and char `Content` values are not tested. `describe` covers the kinds in the cases only.
- Field meanings are inference: `b` as a block number agrees with the prune in `bridge-retention-prune-94`, `h` with a transaction hash, `i` with a log index, and `t` is not established.
- That the flat form feeds arm 44 and the nested form arm 84 is inference from the names; the dispatch from these structs to an arm is not run here.
- Msgpack writers a and b gave the same bytes on every case; what sets them apart is not established.

Next question: which function builds these keys from Ethereum logs, and what `t` holds there.
