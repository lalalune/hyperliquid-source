# RE-008: node #115 per-user p.p and D items (stage 107): pair layouts, fields and types

- Component ID: abci. Question: stage 106 (open PR #6223) found that each per-user value has a p.p sequence of 0x48-byte items (written by `0x4634470`) and a D sequence of 0x18-byte items (written by `0x45fa240`). It left open what each item holds.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6221 and #6223. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, one-byte field names and direct-call targets are observations. "u64", "u32", "i64", "date", "tagged", "default" and "skipped" are inferred labels from the writer code. What the fields mean in the exchange is not claimed. The binary was not executed.
- Scope included: the item writers `0x4634470` and `0x45fa240`; the p.p value `0x448ae20` and its f struct `0x448b410`; the D key writer `0x46f3a10` and its Display `0x44dbf10`; the D value `0x3674da0`; the heads of the integer writers `0x37be790`, `0x4301950` and `0x46ef430`. Scope excluded: the body of the l writer `0x420a0d0`; the date format behind slot `0x64e1158`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_state_items_115.py --check
python3 -m unittest tests.test_user_state_items_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The six `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: both items are written as `[key, value]` pairs

| Sequence | Item writer | Stride | Item at | Value at | Key writer | Value writer |
|---|---|---|---|---|---|---|
| p.p | `0x4634470` | `0x48` (`lea rcx,[rax+0x48]` at `0x46345a5`; divide by 9 with `0x8e38e38e38e38e39` at `0x46344c8`) | `[rsp+0x58]` (`0x46345d3`) | `[rsp+0x60]` = item+8 (`0x46345ae`, `0x46345e0`) | `0x37be790` with `rsi = [item]` (`0x4634779`, `0x463477e`, call `0x4634781`) | `0x448ae20` (`0x4634820`, call `0x463482d`) |
| D | `0x45fa240` | `0x18` (`lea rcx,[rax+0x18]` at `0x45fa375`) | `[rsp+0x60]` (`0x45fa3a3`) | `[rsp+0x58]` = item+8 (`0x45fa37e`, `0x45fa3b0`) | `0x46f3a10` with `rdi = item` (`0x45fa540`, call `0x45fa54d`) | `0x3674da0` (`0x45fa600`, call `0x45fa60d`) |

`0x4634470` writes `[` (`0x463451d`) and `]` (`0x46348f2`) around each pair.

## Evidence 2: p.p value fields

`0x448ae20` writes `{` (`0x448aed2`). Each name is a one-byte string loaded by `lea rsi`.

| Field | Name at | Offset | Writer | Skipped when |
|---|---|---|---|---|
| s | `0x7d082f` | `+0x10` (`0x448ae59`) | `0x41d5380` (i64, #6223) | 0 |
| l | `0x7d0946` | `+0x0` | `0x420a0d0` (checks dword tag `[rdi] == 1` at `0x420a0e5`) | dword `+0x0` is 0 and dword `+0x4` is `0x14` (`0x448ae31`..`0x448ae39`) |
| M | `0x7d13c1` | dword `+0x38` (`0x448ae5d`, `0x448affb`) | `0x4648d30` (`mov edi,dword [rbx]` at `0x4648d76`) → `0x46ef430` | `0x14` (`cmp r8d,0x14` at `0x448ae82`) |
| f | `0x7d13cd` | `+0x18` (`0x448b08e`) | `0x448b410` | `+0x18`, `+0x20`, `+0x28` all 0 (`0x448ae3f`, `0x448ae43`, `0x448ae61`) |
| e | `0x7d0bd9` | `+0x30` (`0x448ae65`, `0x448b0ef`) | `0x4649110` (`mov rdi,qword [rbx]` at `0x4649156`) → `0x4301950` | 0 |

f (`0x448b410`) loads three words (`0x448b42f`, `0x448b432`, `0x448b436`) and writes each through `0x41d5380` when it is not 0: a (`0x7d098e`, `+0x0`), o (`0x7d0929`, `+0x8`), c (`0x7d0c8d`, `+0x10`). All three are i64.

Inference: M is a u32 whose default is 20, not 0. l is an enum or Option with a 4-byte tag; its default is tag 0 with payload 20.

## Evidence 3: D key and value

- Key: `0x46f3a10` builds a format argument with Display `0x44dbf10` (`lea rax` at `0x46f3a79`), calls `core::fmt::write` through slot `0x64df6f0` (`0x46f3a9b`) and writes the closing `"` at `0x46f3ab5`. `0x44dbf10` dereferences to the item and jumps through slot `0x64e1158` (`0x44dbf19`). #6223 found this slot is the date writer that l's Display calls before 'T'. Inference: the D key is a date, written as a JSON string.
- Value: `0x3674da0` writes `{` (`0x3674de7`) and two fields, each through `0x465f980` (u64, #6223): a (`0x79d2d7`, `+0x0`, `0x3674dbf`) and c (`0x79d2d8`, `+0x8`, `0x3674dc2`, `add rbx,0x8` at `0x3674f47`).

## Evidence 4: integer writers

- `0x37be790` (p.p key) and `0x4301950` (e): 20-byte buffer (`mov r12d,0x14` at `0x37be79e`; `mov eax,0x14` at `0x4301951`), `cmp ...,0x2710`, `0x346dc5d63886594b` divide (`0x4301968`), digit table `0x7a1643` (`0x37be7c0`): u64.
- `0x46ef430` (M): 10-byte buffer (`mov eax,0xa` at `0x46ef431`) and `0xd1b71759` divide (`0x46ef447`): u32.
- None of the three has a `neg` (`f7 d9`) in its first 0x20 bytes.

## Implementation and comparison

The tool pins 48 instruction byte runs, 10 field-name loads (each checked to its one-byte name), 18 direct calls and 4 RIP-relative references, and checks the three unsigned writers for a negate. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: mapping the l writer body too (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: p.p is a map u64 → {s: i64, l: tagged, M: u32 (default 20), f: {a, o, c: i64}, e: u64}. D is a map date → {a: u64, c: u64}. Each field is left out when it holds its default.
- Limits: the payload type of l (`0x420a0d0`) and the exact date text format are not mapped. What each field means (for example, positions, fills or daily volume) is not claimed.
- Next lead: map the l writer `0x420a0d0`.
