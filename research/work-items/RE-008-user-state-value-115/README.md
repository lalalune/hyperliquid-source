# RE-008: node #115 per-user state value `0x3beac00` (stage 106): the six fields and their types

- Component ID: abci. Question: stage 105 (open PR #6221) found that `Clearinghouse.user_states.user_to_state` writes each entry as a `[key, value]` pair and passes the value to `0x3beac00`. It left open which fields the value has and what type each one is.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6219 and #6221. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, one-byte field names and direct-call targets are observations. "Signed", "unsigned", "i64", "u64", "date-time", "sequence", "default" and "skipped" are inferred labels from the writer code. What u, p, D, l, S and r mean in the exchange is not claimed. The binary was not executed.
- Scope included: the field writes of `0x3beac00`; the p struct `0x4206910`; the D sequence head `0x464d090`; the S struct `0x36752b0`; the integer writers `0x41d5380` and `0x46ef580`; the l writer `0x4592eb0` and the head of its Display `0x46dd720`. Scope excluded: the item writers `0x4634470` (p.p) and `0x45fa240` (D), the time half of l. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_state_value_115.py --check
python3 -m unittest tests.test_user_state_value_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: six fields, each skipped at its default

`0x3beac00` is a pretty JSON writer (it writes `": "` and newlines). Each field name is a one-byte string loaded by `lea rsi` and `mov edx,1`.

| Field | Name at | Offset | Writer call | Skipped when |
|---|---|---|---|---|
| u | `0x7ba759` | `+0x48` | `0x3beaddf` → `0x41d5380` | value 0 (`0x3beac14`, `0x3bead75`) |
| p | `0x7b9bbb` | `+0x0` | `0x3beae7e` → `0x4206910` | p.p equals the empty value and n is 0 |
| D | `0x7bad69` | `+0x28` | `0x3beaed4` → `0x464d090` | empty (`lea rdi,[r13+0x28]` at `0x3beac5b`) |
| l | `0x7b9af7` | `+0x68` | `0x3beaf6f` → `0x4592eb0` | dword `+0x68` is `0xf6401a`, `+0x6c` and `+0x70` are 0 (`0x3beac88`) |
| S | `0x7bad6a` | `+0x50` | `0x3beafe9` → `0x36752b0` | `+0x50` and `+0x58` are both 0 (`0x3beac9f`) |
| r | `0x7b9b44` | `+0x60` | `0x3beb027` → `0x465f980` | value 0 (`0x3beacc2`, `0x3beb00f`) |

Inference: the fields use serde "skip if default". The `0xf6401a` date is the l default.

## Evidence 2: integer types

- `0x41d5380` (u) has `neg rcx` at `0x41d5391` and `cmovs rcx,rsi` at `0x41d5394`. It writes a sign for negative values: i64.
- `0x465f980` (r) formats through `0x46ef580` (call `0x465f9d0`). `0x46ef580` starts `push rbx; mov eax,0x14; cmp rdi,0x2710` and has no `0xf7` (neg) byte in its first 0x10 bytes: u64.

## Evidence 3: p, D and S

- p (`0x4206910`): field `p` (name `0x7c828e`) at `+0x0` through `0x46649a0` (call `0x4206a12`). That is a two-slice sequence of 0x48-byte items (`lea rcx,[rcx+rcx*8]`, `lea rdi,[rdx+rcx*8]` at `0x4664a54`), each written by `0x4634470` (call `0x4664aab`). Field `n` (name `0x7c89f4`) at `+0x20` (`add rbx,0x20` at `0x4206a33`) through `0x4648c20` → `0x46ef580`: u64.
- D (`0x464d090`): a two-slice sequence of 0x18-byte items (`lea rcx,[rcx+rcx*2]`, `lea rdi,[rdx+rcx*8]` at `0x464d144`), each written by `0x45fa240` (call `0x464d19b`).
- S (`0x36752b0`): field `s` (name `0x79cc47`) at `+0x0` through `0x465f980`: u64; field `r` (name `0x79c5d3`) at `+0x8` (`add rbx,0x8` at `0x3675457`) through `0x4654de0` → `0x46ef580`: u64.

Inference: "two-slice" matches a ring buffer (VecDeque) iterated as two contiguous halves.

## Evidence 4: l is a date-time

`0x4592eb0` loads Display `0x46dd720` (`lea rax` at `0x4592f05`) and calls `core::fmt::write` through slot `0x64df6f0` (`0x4592f27`). `0x46dd720` calls the date writer through slot `0x64e1158` (`0x46dd733`) and then writes `mov esi,0x54` ('T') at `0x46dd744`. This is the same date, then 'T' shape as #6077.

## Implementation and comparison

The tool pins 19 instruction byte runs, 10 field-name loads (each checked to its one-byte name), 15 direct calls and 3 RIP-relative references, and checks that `0x46ef580` has no negate. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: mapping the item writers too (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: each per-user value has up to six fields: u (i64), p ({p: sequence of 0x48-byte items, n: u64}), D (sequence of 0x18-byte items), l (date-time), S ({s: u64, r: u64}) and r (u64). Each is left out when it holds its default.
- Limits: the field names inside the 0x48-byte p.p items (`0x4634470`) and the 0x18-byte D items (`0x45fa240`) are not mapped; the time half of l and its fraction format are not mapped; what each field means (for example, positions or balances) is not claimed.
- Next lead: map the p.p item writer `0x4634470` or the D item writer `0x45fa240`.
