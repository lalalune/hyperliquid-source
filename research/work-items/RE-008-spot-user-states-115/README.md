# RE-008: node #115 SpotClearinghouse field `user_states` is a sequenced map of a 20-byte key to {b, D, S} (129th stage)

- Component ID: abci. Question: open PR #6594 showed that field 1 (`user_states`) of the struct `SpotClearinghouse` is read by `0x31541c0`. Open PR #6584 showed that the perp clearinghouse field `user_states` is read by `0x32daf90`. What does `0x31541c0` read, and how does it differ from the perp side?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6594 and #6584. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, relocations, function starts from `.eh_frame_hdr`, and strings are observations. "sequenced map", "pair", "user key" and "optional" are inferred labels. The binary was not executed.
- Scope included: the top level of `0x31541c0`, its map refusal `0x45dffb0`, its sequence reader `0x46fa510`, the pair reader `0x32a82b0`, and the key match, field arms and duplicate checks of the value reader `0x3208ad0`. Scope excluded: the bodies of the three field decoders, the hash-map insert, the value reader's sequence form, the default values, and what `b`, `D` and `S` stand for. No gate changes.

## Result

| Step | Address | Result |
|---|---|---|
| Caller | `0x31b62de` | SpotClearinghouse arm 1 (`user_states`) calls `0x31541c0` (#6594) |
| Marker dispatch | `0x3154217`, `0x3154225` | A fixmap (below `0x90`) goes to `0x45dffb0` (call at `0x31542fe`). A fixarray (`0x90` to `0x9f`) goes to `0x46fa510` (call at `0x31543a9`). |
| Map refusal | `0x45dffb0` | Builds an `invalid type` error (tag `0xb`) through visitor table `0x6490a30`. Slot `0x6490a48` is relocated to `0x46dd930`, which writes the 15-byte text `a sequenced map`. |
| Sequence | `0x46fa510` | First allocation capped at `0x2762` entries of `0x70` bytes. Each element is read through `0x32a82b0` (call at `0x46fa65b`). |
| Pair | `0x32a82b0` | From an array: an empty array is an error (`0x32a845c`). The key is read through `0x32e36c0` with length `0x14` (`0x32a8496`, call at `0x32a84bf`). An array with one element is an error (`0x32a879b`). The value is read through `0x3208ad0` (call at `0x32a87c3`). |
| Value key read | `0x3208fb8` | Calls through slot `0x64dfca8`. A one-byte key is matched inline: `b` is field 0, `D` is field 1, `S` is field 2, any other key is field 3. The index goes to table `0x6e6eb4`. |

Value fields (table `0x6e6eb4`). Each arm 0 to 2 first tests whether its field is already set. If so, it jumps to a block that loads the one-byte name and the template `duplicate field `...`` (`0x43351a`).

| Index | Key | Arm | Decoder |
|---|---|---|---|
| 0 | `b` | `0x3208d46` | `0x31a73f0` |
| 1 | `D` | `0x3209338` | `0x3215260` |
| 2 | `S` | `0x32093df` | `0x31c32d0` |
| 3 | any other key | `0x32093b4` | `0x31d5e50` (skip) |

- The function `0x3208ad0` has no load of the template `missing field `...`` (`0x4325c4`). None of the three fields has a missing-field error, so they are probably optional. The default values are not proven.
- `0x3215260` and `0x31c32d0` are the same decoders that the second per-user value visitor `0x30bcb40` calls for `D` and `S` (#6582). The decoder of `b` is not used by that visitor.
- `0x32e36c0` is the same 20-byte key reader that `0x3314a40` (#6584) and `0x2f660a0` (#6591) use.

## Comparison with the perp side

| | Perp clearinghouse (#6584) | SpotClearinghouse (this packet) |
|---|---|---|
| `user_states` decoder | `0x32daf90`, which loads `struct UserStates with 6 elements` (record `0x64645c0`, checked at `0x32dbf0f`) | `0x31541c0`: no struct. It reads a sequenced map directly. |
| Path to a per-user value | `user_states.user_to_state[user]` | `user_states[user]` |
| Per-user value keys | `u, p, D, l, S, r` (#6239, #6582) | `b, D, S` |

Correction to #6594: its README calls `0x3274e70` the perp `user_states` reader. `0x3274e70` is the perp `Clearinghouse` visitor (it loads `struct Clearinghouse with 19 elements`); its field `user_states` is read by `0x32daf90`, as #6584 shows.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/spot_user_states_115.py --check
python3 -m unittest tests.test_spot_user_states_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The fourteen `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 17 byte runs, each with its meaning. It checks 9 branch and call targets, the map refusal's visitor table, slot relocation and expected text, the key slot, 4 field-table entries, 4 decoder calls, 3 duplicate branches with the name, stored length and template load in each duplicate block, the absence of any missing-field template load in `0x3208ad0`, the perp `UserStates` record with its relocation and length, and the function that holds each of 50 checked sites. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the decoder on a sample state (not allowed for this repository).

## Results and limitations

- Result: SpotClearinghouse `user_states` is a sequenced map from a 20-byte key to a value with three optional one-byte keys `b`, `D` and `S`. The perp side wraps its map in the 6-field struct `UserStates`; the spot side does not.
- Limits: the field decoder bodies, the hash-map insert, the value reader's sequence form, the defaults, and the meaning of `b`, `D` and `S` are not mapped. That the key is a user address is an inference from the key length and the matching perp path.
