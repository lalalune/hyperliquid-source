# RE-008: node #115 per-user value (111th stage): the map visitor fills the writer's layout

- Component ID: abci. Question: open PR #6223 found the writer `0x3beac00`, which reads the per-user value at u `+0x48`, p `+0x0`, D `+0x28`, l `+0x68`, S `+0x50`, r `+0x60` and skips each field at its default. Open PR #6230 found that the map visitor `0x1a212f0` matches the same six keys as field indexes 0..5, but did not follow the visitor's stores. Does the visitor build the layout that the writer reads, and with the defaults that the writer skips?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6223 and #6230. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, call targets, strings and the decoded copy are observations. "Decoder", "seen flag", "default", "array form", "VecDeque" and "date 1970-01-01" are inferred labels. The binary was not executed.
- Scope included: the field-index jump table and the seven arms of `0x1a212f0`; the end-of-map defaults; both exits that copy the value to the output (`rbx`); the key match of the p decoder `0x191bf90` (with its byte-key fallback `0x184c9b0`) and of the S decoder `0x1adf620`. Scope excluded: the D decoder `0x18d4f40` and its item decoder, the position item decoder below `0x191bf90`, the u and l decoder bodies, and the array form after its first two elements. No gate changes.

## Result

| Key | Index | Arm | Decoder | Stack value | Output | Default when missing | Writer skips when (#6223) |
|---|---|---|---|---|---|---|---|
| `u` | 0 | `0x1a219cd` | `0x17cb550` (name `Ntli`, 4 bytes) | `rsp+0x180` | `+0x48` | 0 | value 0 |
| `p` | 1 | `0x1a22018` | `0x191bf90` | `rsp+0x138` | `+0x0` | cap 0, ptr 8, head 0, len 0, n 0 | p.p empty and n 0 |
| `D` | 2 | `0x1a2213a` | `0x18d4f40` | `rsp+0x160` | `+0x28` | cap 0, ptr 8, head 0, len 0 | empty |
| `l` | 3 | `0x1a221cb` | `0x17ce890` (name `Time`, 4 bytes) | `rsp+0x1a0` | `+0x68` | dword `0xf6401a`, then 8 zero bytes | `+0x68` is `0xf6401a`, `+0x6c` and `+0x70` are 0 |
| `S` | 4 | `0x1a220d5` | `0x1adf620` | `rsp+0x188` | `+0x50` | 0, 0 | `+0x50` and `+0x58` both 0 |
| `r` | 5 | `0x1a2222a` | integer read through slot `0x64e2580` | `rsp+0x198` | `+0x60` | 0 | value 0 |

All six offsets match #6223. All six defaults are the values the writer skips. New: the p decoder also accepts the long keys `perp_to_position` (p.p) and `n_open_positions` (p.n).

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_value_visitor_115.py --check
python3 -m unittest tests.test_user_value_visitor_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The nine `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: one arm per field, one stack slot per field

- `lea rcx,[0x5227e0]` at `0x1a21c8b` loads the field-index table. Its seven entries go to the arms in the table above, and index 6 to the ignore arm `0x1a220ad` (skip one value through `0x19ccaf0`).
- Each arm first tests whether the field was already seen (this is the `duplicate field` path of #6230), then calls its decoder into `[rsp+0x80]`, then moves the result to its slot. Examples: S stores `[rsp+0x88]` to `[rsp+0x1d8]` and `[rsp+0x90]` to `[rsp+0x1d0]` and sets `[rsp+0x108]=1`; l stores dword `[rsp+0x84]` to `[rsp+0x100]` and qword `[rsp+0x88]` to `[rsp+0x1e0]`.
- p and D are kept as a 4- or 5-word value with a `0x8000000000000001` "not seen" niche. Their free paths size the old buffer as cap × `0x48` (`lea rsi,[rax+rax*8]` after `shl rax,3`, `0x1a22098`) and cap × `0x18` (`0x1a221b6`). These are the item sizes #6223 found in the writer.

## Evidence 2: the stack value is copied to the output as one block

- After the map ends, `0x1a2248c..0x1a224d6` and `0x1a226da..0x1a2272d` pick each slot or its default (`cmove`) and build the value at `[rsp+0x138..0x1b0]`.
- The success exit `0x1a227bb..0x1a2282e` copies it to `rbx+0x0..0x78`. The tool decodes each load and store byte by byte: every output byte comes from `rsp+0x138` plus the same offset.
- The array form (fixarray marker, same function) calls the u decoder first (`0x1a214e8`, same `Ntli` name) and the p decoder second (`0x1a2151e`). It writes the same stack slots at `0x1a2253a` and leaves through a second exit (`0x1a2289d`) that stages the value at `[rsp+0x80..0xf4]` and then copies it to `rbx`. The tool decodes this relay too: it gives the same 120-byte map. One path of the array form stores the l default `0xf6401a` at `0x1a22419`.

## Evidence 3: defaults are the writer's skip values

- No missing field is an error in the map path. u and r default to 0 (`cmove r10,rax`, `cmove rdx,rax`). p and D default to cap 0, pointer 8, the rest 0, which is the empty value the writer builds at `0x3beac1d` and `0x3beac5f` to compare against. S defaults to 0, 0 (`cmove r12,rdi`, `cmove r13,rdi`).
- l defaults to `mov r8d,0xf6401a` (`0x1a2270f`) and `r11 = 0`. The writer tests the same constant (`mov ecx,0xf6401a` at `0x3beac88`). Inferred: `0xf6401a >> 13` is 1970 and the ordinal bits are 1, so this is the date 1970-01-01 in chrono's packed `NaiveDate` form.

## Evidence 4: p and S decoders

- p `0x191bf90`: after UTF-8 check (slot `0x64dfca8`, `0x191c614`), a key of length 16 is compared with `pcmpeqb` to `0x456010` `perp_to_position` (index 0) and `0x450800` `n_open_positions` (index 1). A key of length 1 maps `p` to 0 and `n` to 1. Any other key is index 2 (ignore). If the key is not UTF-8, the bytes go to `0x184c9b0`, which matches the same four keys with byte compares; the tool decodes the two 16-byte chains from the instruction bytes.
- S `0x1adf620`: two key sites (`0x1adfb3e`, `0x1adfbe0`), each after a length-1 guard, map `s` to 0 and `r` to 1. The function has no `pcmpeqb` constant compare, and neither key site has a second length arm: no long name was found.

## Implementation and comparison

The tool pins 30 instruction byte runs, decodes the field-index table, 7 direct calls and 2 slot calls, 2 name loads, 2 `pcmpeqb` constants, the byte-key chains, and both output copies (byte by byte, through the staging slots). Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Where a mutation sits inside a pin, the test removes that pin so the derived check must catch it. Alternatives considered: emulating the visitor on a crafted MessagePack value (not allowed for this repository); mapping the D and position item decoders too (bounded out).

## Results and limitations

- Result: the map visitor `0x1a212f0` builds exactly the layout that the writer `0x3beac00` reads, and a missing field gets exactly the value that the writer leaves out. The p field is `{p: perp_to_position, n: n_open_positions}`. S keys are one byte only.
- Limits: the D item keys and the position item keys under `perp_to_position` are not mapped here; the u and l decoder bodies (`Ntli`, `Time`) are not read, so their meaning is not claimed; the array form is checked only for its first two decoders, one default, the slot stores and its exit copy.
- Next lead: the D decoder `0x18d4f40` and its item decoder, to check whether the D item keys also have long-name aliases.
