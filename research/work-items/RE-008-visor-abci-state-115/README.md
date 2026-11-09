# RE-008: node #115 visor_abci_state value and its four writers (35th stage)

- Component ID: abci. Question: open PR #6002 found that `hyperliquid_data/visor_abci_state.json` is written by the wrapper `0x5942b40` (four callers) and by `0x5a39630`, both through the value writer `0x50de010`. It left open what value is written and how the callers differ.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6001 and #6002. It imports helpers from the merged `tools/freeze_snapshot_115.py` only.
- Claim status: instruction bytes, string bytes, relocations, Location records and direct-call censuses are observations. "Visor state", "engine box", "u64 / Option / time serializer", "consensus time" and "wall clock" are inferred labels from the field names, call shapes and earlier packets. The binary was not executed.
- Scope included: the JSON serializer `0x51adf60` up to its last field; the value fill and wrapper call in `0x5443930`, `0x59ec200`, `0x5a07ec0` and `0x5a08720`; the name slice and Location each passes. Scope excluded: the rmp serializer `0x51ae110` body, the per-field serializers, `0x56185e0` (the condition byte in `0x5443930`), and `0x5a39630` after its `0x50de010` call. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/visor_abci_state_115.py --check
python3 -m unittest tests.test_visor_abci_state_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: one value type, six fields

`0x51adf60` has one direct caller, `0x50de1d8` in `0x50de010`. `0x50de010` has two direct callers: `0x5942b6f` (the wrapper) and `0x5a396ef` (`0x5a39630`). So every writer of `visor_abci_state.json` serializes the same type.

`0x51adf60` writes `{` and then six fields, each with a `lea rsi` to the name, a `mov edx` length and a field pointer `rbx+off`:

| Order | Name (string, length) | Value offset | Serializer |
|---|---|---|---|
| 1 | `hardfork_version` (`0x4504e0`, 16) | `+0x10` | `0x507d670` |
| 2 | `initial_height` (`0x91f96f`, 14) | `+0x18` | `0x507d670` |
| 3 | `height` (`0x91f97d`, 6) | `+0x20` | `0x507d670` |
| 4 | `scheduled_freeze_height` (`0x91f983`, 23) | `+0x0` | `0x509b5b0` |
| 5 | `consensus_time` (`0x91f99a`, 14) | `+0x28` | `0x508f390` |
| 6 | `wall_clock_time` (`0x91f9a8`, 15) | `+0x34` | `0x508f390` |

Inference: `0x507d670` is the u64 field serializer (110 direct callers), `0x509b5b0` an Option field serializer (16-byte value), `0x508f390` the 12-byte date/seconds/fraction time serializer.

## Evidence 2: how the callers fill it

All four callers build the 0x40-byte value the same way (shown for `0x5443930`, box = `[engine +0x450]`):

- `movdqu` of box `+0x10..+0x20`, then `pshufd 0x4e` (swap halves) to value `+0x10`: hardfork_version = box `+0x18`, initial_height = box `+0x10`.
- height = box `+0x28` → value `+0x20`.
- consensus_time = box `+0x60` (qword) and `+0x68` (dword) → value `+0x28`.
- wall_clock_time = the tuple from slot `0x64e0990` (`R_X86_64_RELATIVE` → `0x1629690`, the wall-clock provider of #5045) → value `+0x34`.
- scheduled_freeze_height (16 bytes) → value `+0x0`.

| Caller | Wrapper call | Location | scheduled_freeze_height from |
|---|---|---|---|
| `0x5443930` | `0x5443a82` | `node/src/node.rs:659:50` | box `+0x10e8` |
| `0x59ec200` | `0x59ec380` | `node/src/node.rs:659:50` | box `+0x10e8` |
| `0x5a07ec0` | `0x5a08250` | `l1/src/abci/engine.rs:316:46` | box `+0x10e8` |
| `0x5a08720` | `0x5a08ab0` | `l1/src/abci/engine.rs:316:46` | box `+0x1c58` |

Every caller passes the name slice `visor_abci_state` (16 bytes, `0x4564d0`).

`0x5a08720` reads box `+0x1c58`, the field only the freeze setter `0x54c9b80` writes (#5970). The other three read `+0x10e8`. The byte the two engine steps pass to slot `0x64e1220` moves by the same amount: box `+0xb9a` in `0x5a07ec0`, box `+0x170a` in `0x5a08720`. Both differences are 0xb70. Inference: `0x5a07ec0` and `0x5a08720` are two builds of the same step for two box layouts that differ by a 0xb70-byte field before these offsets; 0xb70 is also the size of the output setter result in #5908. The tool checks both differences but does not prove the layout claim.

In `0x5443930` the write happens only when byte `[rsp+0x3b0]`, set by `0x56185e0`, is non-zero (`0x54439cc`). `0x56185e0` is not mapped.

## Implementation and comparison

The tool pins 6 field-offset instructions, 6 length moves, 19 caller-fill instructions, 6 name references and serializer calls, 4 wrapper calls with their name slices, Locations and clock calls, the clock slot relocation, and the direct-call censuses of the wrapper, the value writer and both serializers. Tests change one byte in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: decoding serde field tables generically (no table here; the names are inline `lea` arguments); emulation (not allowed).

## Results and limitations

- Result: `visor_abci_state.json` is one object `{hardfork_version, initial_height, height, scheduled_freeze_height, consensus_time, wall_clock_time}`. Three writers take the freeze height from box `+0x10e8`, one from `+0x1c58`.
- Limits: the meaning of box `+0x10e8` in the three non-freeze writers; the per-field serializers' exact output (number vs string, time format); the rmp serializer; what `0x5a39630`'s line writer records per entry after its JSON write (its loop around `0x4e3fe00` is not mapped); the condition `0x56185e0` sets.
- Next lead: what box `+0x10e8` holds in the `0x5a07ec0` layout, and whether it is the same field as `+0x1c58` in the other layout.
