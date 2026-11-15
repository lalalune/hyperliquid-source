# RE-008: node #115 per-user value (113th stage): the D writer sends a list of [date, {a, c}] pairs

- Component ID: abci. Question: open PR #6319 found that the D decoder `0x18d4f40` reads a date-keyed map of `{a, c}` (entry `0x18` bytes: key `+0x0`, `a` `+0x8`, `c` `+0x10`). Open PR #6223 found that the per-user value writer `0x3beac00` writes D (`+0x28`) through `0x464d090`, which writes `0x18`-byte items through `0x45fa240`. Neither PR read the writer items. Does the writer use the same entry layout, write `a` before `c`, and leave out the same defaults?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6223 and #6319. It does not depend on their files.
- Claim status: instruction bytes, call and jump targets, immediates, offsets and one-byte names are observations. "Small form", "large form", "BTree", "list of pairs", "date" and "skipped" are inferred labels. The binary was not executed.
- Scope included: the D writer `0x464d090` (form choice), the pair writer `0x45fa240`, the key writer `0x46f3a10` and its closure `0x44dbf10`, the value writer `0x3674da0`. Scope excluded: the large-form iterator body `0x37c4c80`, the date Display behind slot `0x64e1158`, the indent and error paths. No gate changes.

## Result

| Part | Function | What it does |
|---|---|---|
| Form choice | `0x464d090` | first word `0x8000000000000000` (the only value where `neg` overflows) is the large form: root `+0x8`, height `+0x10`, length `+0x18`, iterated by `0x37c4c80`. Any other value is the small form: cap `+0x0`, ptr `+0x8`, head `+0x10`, length `+0x18`, two slices of `0x18`-byte entries, iterator tag 2 |
| Pair writer | `0x45fa240` | writes `[`, then for each entry `[`, the key (`0x46f3a10`), `,\n`, the value (`0x3674da0`), `]`. Small form: key = entry `+0x0`, value = entry `+0x8`, next entry = `+0x18` |
| Key writer | `0x46f3a10` | writes `"`, the key through `core::fmt::write` (slot `0x64df6f0`) with closure `0x44dbf10`, then `"`. The closure jumps through the date slot `0x64e1158`, the same slot the l date-time Display calls (`0x46dd733`, #6223) |
| Value writer | `0x3674da0` | writes `{`, then `a` (value `+0x0`) and `c` (value `+0x8`) through the u64 field writer `0x465f980`; each is left out when 0; when both are 0 it writes `{}` |

So the writer and the decoder agree: the same `0x18`-byte entry, the key at `+0x0`, `a` at entry `+0x8`, `c` at entry `+0x10`, `a` before `c`. The writer leaves out a 0 field and the decoder fills a missing field with 0, so a written value reads back the same. The two forms match the decoder's collector of #6319: up to `0x40` entries `(cap, ptr, 0, len)`, else tag `0x8000000000000000`.

The writer always sends D as a list of pairs. #6319 shows that the decoder takes that list form (its array visitor) as well as a map.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_value_d_writer_115.py --check
python3 -m unittest tests.test_user_value_d_writer_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The nine `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: two forms

- `0x464d0da`: `mov rax,[r14]; mov rcx,rax; neg rcx; jno 0x464d109`. `neg` overflows only for `0x8000000000000000`, so only that value falls through to the large path.
- Large path: root `[r14+0x8]` (`0x464d0e5`), height `[r14+0x10]` (`0x464d0fb`), length `[r14+0x18]` (`0x464d0f7`, used only when the root is not 0). The iterator tag is 0 or 1 (root present). `0x45fa240` takes the count from the length and gets each entry from `0x37c4c80` (call `0x45fa395`), which returns the key pointer in `rax` and the value pointer in `rdx`.
- Small path (`0x464d109`): length `[r14+0x18]`, head `[r14+0x10]`, ptr `[r14+0x8]`; the two slices are built with `lea rcx,[rcx+rcx*2]; lea rdi,[rdx+rcx*8]` (`0x18`-byte entries) and tag 2 (`mov r8d,2`, `0x464d15c`). `0x45fa240` compares the tag with 2 (`0x45fa27d`) and counts entries as bytes / 8 × `0xaaaaaaaaaaaaaaab` (bytes / `0x18`).

## Evidence 2: list of [key, value] pairs

- Outer `[` at `0x45fa2ed`. Each small-form entry: `lea rcx,[rax+0x18]` (next entry, `0x45fa375`), `lea rdx,[rax+0x8]` (value, `0x45fa37e`). Both paths store the key pointer at `[rsp+0x60]` and the value pointer at `[rsp+0x58]` (`0x45fa3a3`, `0x45fa3b0`).
- Pair `[` at `0x45fa4ca`; key: `mov rdi,[rsp+0x60]; call 0x46f3a10` (`0x45fa540`, `0x45fa54d`); `,\n` (`mov word ...,0x0a2c`, `0x45fa57d`); value: `mov rdi,[rsp+0x58]; call 0x3674da0` (`0x45fa600`, `0x45fa60d`); pair `]` at `0x45fa6d2`. Between the key call and the value call there is only the separator and the indent loop, so the key is written first.

## Evidence 3: the key is a quoted date

- `0x46f3a10` writes `"` (`0x46f3a4d`), loads the closure `0x44dbf10` (`lea rax`, `0x46f3a79`), and calls `core::fmt::write` through slot `0x64df6f0` (`0x46f3a9b`). It then writes `"` (`0x46f3ab5`).
- `0x44dbf10` is three loads and `jmp [0x64e1158]` (`0x44dbf19`). `0x46dd720`, the Display of the l date-time field (#6223), calls the same slot at `0x46dd733` for its date half.

## Evidence 4: a then c, each left out at 0

- `0x3674da0`: `mov r13,[rdi]` (a, `0x3674dbf`), `mov r15,[rdi+0x8]` (c, `0x3674dc2`). It writes `{` (`0x3674de7`).
- `mov rcx,r15; or rcx,r13; je 0x3674e3d` (`0x3674df2`): both 0 → write `}` at `0x3674e4e` and return.
- `test r13,r13; je 0x3674f37` (`0x3674e05`): a = 0 → go to the c test. Otherwise name `a` (`0x79d2d7`, length 1) and value pointer `rbx` (value `+0x0`) go to `0x465f980` (`0x3674e20`). Then `test r15,r15; jne 0x3674f42` (`0x3674e32`).
- `0x3674f39`: `test r15,r15; je 0x3674e65` (c = 0 → end). `0x3674f42`: `add rbx,0x8`, name `c` (`0x79d2d8`, length 1), call `0x465f980` (`0x3674f5d`).
- `0x465f980` formats through `0x46ef580` (call `0x465f9d0`), the unsigned formatter of #6223: a and c are written as u64.

## Implementation and comparison

The tool pins 27 instruction byte runs and derives, from the bytes, 7 direct calls, 5 jump targets, 6 RIP-relative references, 2 one-byte names, 9 immediates (form tag, entry stride, value offset, c offset, name lengths) and 8 JSON punctuation stores. Tests mutate one byte at a time in a copy of the image and expect rejection (11 mutation tests). Ten of them hit a derived check, not a pin; one (`neg` → `not`) is caught only by its pin. Alternatives considered: writing a crafted value by running the code (not allowed for this repository); reading the large-form iterator `0x37c4c80` (bounded out).

## Results and limitations

- Result: D is written as `[[date, {a, c}], ...]`. The writer reads the same entry layout the decoder of #6319 builds, writes `a` before `c`, and leaves out each 0 field, which the decoder reads back as 0.
- Limits: the date text format behind slot `0x64e1158` is not decoded; the large-form iterator `0x37c4c80` is pinned by its call only, and its key/value pointer return is an inference from its use; what `a` and `c` mean is not claimed.
- Next lead: the p.p item writer `0x4634470` (0x48-byte items of the p field, #6223).
