# RE-008: node #115 Clearinghouse.user_states and its per-user entries (stage 105)

- Component ID: abci. Question: #6219 named Clearinghouse field 1 `user_states` at element `+0x60` (0xe8 bytes, up to `oracle` at `+0x148`). This packet names the fields inside `user_states`, the layout of its `user_to_state` entries, and the six one-letter fields of each per-user value.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #6218 and #6219; it does not depend on their files.
- Claim status: names, lengths, displacements, call targets, the entry stride and the key length are observations from bytes. Reading displacements as struct field offsets, and the 20-byte key as a user address, are inferences from the serializer shape. The binary was not executed.

## Reproduce

```
python3 tools/clearinghouse_user_states_115.py --check
python3 -m unittest tests.test_clearinghouse_user_states_115
```

The tool reads the ELF only. The three `*.objdump.txt` files (GNU objdump 2.42) are for review; the tool does not read them.

## user_states (serializer `0x446b620`)

The Clearinghouse serializer passes `lea rdi,[rbx+0x60]` (`0x4482244`) and calls `0x446b620` (`0x4482279`). Each name is loaded with `lea rsi,[rip+…]` and `mov edx, len`; the value comes from `rbx` plus the offset. Two names are loaded inside one-field helpers.

| Field | Offset | Value writer |
|---|---|---|
| user_to_state | +0x0 | `0x4663f30` |
| open_order_tracker | +0x48 | helper `0x44f4610` |
| asset_to_oi_szi | +0x90 | `0x4664840` |
| users_with_positions | +0xb0 | `0x4614d00` |
| ar | +0xc8 | helper `0x44f4ad0` |
| check_all_users_for_liquidatables | +0xe0 | `0x4649840` |

## user_to_state entries (`0x4663f30`)

- Entries are 0x98 bytes (`imul rax,rbx,0x98` at `0x4663fd1`), written as a JSON array of `[key, value]` pairs.
- Key: the 20 bytes at entry `+0x80` (`add rax,0x80` at `0x4664112`, `mov ecx,0x14`), hex-encoded into a 0x2a-byte buffer (`0x` plus 40 digits) by `0x3ee7590`.
- Value: entry `+0x0`, written by `0x3beac00` (`0x466425d`).

## Per-user value (`0x3beac00`)

Six one-letter fields. The writer reloads the entry base into r13 (`0x3bead78`) and entry `+0x28` into r14 (`0x3bead7d`); each field skips when its value is empty or zero.

| Field | Offset | Value writer | Pinned by |
|---|---|---|---|
| u | +0x48 | `0x41d5380` | `mov rax,[rdi+0x48]` at `0x3beac14`, reloaded at `0x3beadda` |
| p | +0x0 | `0x4206910` | `mov rdi,r13` at `0x3beae78` |
| D | +0x28 | `0x464d090` | `lea rdi,[r13+0x28]` at `0x3beac5b`, `mov rcx,r14` |
| l | +0x68 | `0x4592eb0` | `lea rbx,[r13+0x68]` at `0x3beaf26` (12-byte date-time; unset `0xf6401a` test at `0x3beac88`) |
| S | +0x50 | `0x36752b0` | `lea rdi,[r13+0x50]` at `0x3beafb4` |
| r | +0x60 | `0x465f980` | `add r13,0x60` at `0x3beb00f`, `mov rcx,r13` |

## Results and limitations

- Result: `user_states` is a six-field struct; its `user_to_state` field is a list of (per-user value, 20-byte key) entries, and each value has six one-letter fields at the offsets above.
- No offset used in earlier stages falls inside `user_states` (+0x60..+0x148).
- Limits: the value types behind the one-letter fields (what `u`, `p`, `D`, `S`, `r` hold), the container type of `users_with_positions`, `asset_to_oi_szi`, `open_order_tracker` and `ar`, and the `oracle` field (`+0x148`, serializer `0x38b8ba0`) are not mapped. The skip conditions are read from the field-count arithmetic and are not pinned per field.
- Next lead: the value writers `0x4206910` (`p`) and `0x464d090` (`D`).
