# RE-008: node #115 position field `l` is the enum Leverage (108th stage)

- Component ID: abci. Question: open PR #6224 found that the per-user `p.p` item value writes field `l` (`+0x0`, dword tag at `+0x0`, payload at `+0x4`) with `0x420a0d0`, and skips it when the tag is 0 and the payload is `0x14`. It left open what the tag and payload mean.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6223 and #6224. It does not depend on their files.
- Claim status: instruction bytes, string bytes, relocations, `&str` lengths, FDE extents and call or reference censuses are observations. "Cross", "Isolated", "leverage" and "raw USD margin" as meanings are inferred from the names in the binary and the field use. The binary was not executed.
- Scope included: the JSON writer `0x420a0d0`, the MessagePack writer `0x4209b80`, their one caller each, the two four-entry name lists and their users. Scope excluded: the deserializer bodies (`0x420aa40`, `0x41fe720`, `0x41fe840`, `0x3f7a920`, `0x3fb7ab0`), the users of `"C"` and `"l"` outside these writers, and the other `p.p` fields (`s`, `e`, `f`, `M`). No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/position_l_field_115.py --check
python3 -m unittest tests.test_position_l_field_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: two writers, one caller each

- `0x420a0d0` has one direct call, `0x448afdc`, in the JSON item writer `0x448ae20` (#6224). It passes `rbx` (the item value) as `rdi`.
- `0x4209b80` has one direct call, `0x448ab8f`, in `0x448aa30`. Before it, `0x448ab66` writes the key `"l"` (`0x7d0946`, length 1) with `0x41c6110`.

## Evidence 2: the value shape

| Tag `dword [+0x0]` | JSON (`0x420a0d0`) | MessagePack (`0x4209b80`) |
|---|---|---|
| 1 | `{"I": {"l": u32 +0x4, "u": i64 +0x8}}` | `"I"`, `"l"` `[r15+4]`, `"u"` `[r15+8]` |
| other | `{"C": u32 +0x4}` | `"C"`, `[r15+4]` |

- JSON tag 1: `0x420a12b` saves `rdi` to `[rsp]`, `0x420a236` reloads it into `r15`. `"I"` (`0x7c84d3`, `edx = 1`) goes to `0x46708b0`; `"l"` (`0x7c8413`) with `lea rcx, [r15+4]` goes to `0x4648d30` (u32, #6224); `"u"` (`0x7c841b`) goes to `0x4713ba0`; then `mov rsi, [r15+8]` goes to `0x41d5380` (i64, #6223).
- JSON other tag: `0x420a0e1` sets `r14 = rdi+4`, `0x420a197` saves it to `[rsp+8]`; `"C"` (`0x7c842c`) goes to `0x46708b0`; `0x420a49e` loads `edi = [rax]` and calls `0x46ef430` (u32 formatter, #6224).
- MessagePack: `0x4209b8e` sets `r15 = rsi`, `0x4209b9e` compares `[rsi]` with 1. Keys go to `0x41c6110`. u32 values `mov edx, [r15+4]` (`0x4209c4e`, `0x4209cca`) go to `0x3d517e0`; `mov rdx, [r15+8]` (`0x4209d07`) goes to `0x3d50670`.
- In `.text`, `lea` references to `"I"` and `"u"` appear only in these two writers.

## Evidence 3: the names

- The `&str` list at `0x6483c28` holds `l`, `leverage`, `raw_usd`, `u`. One user, `0x420aa40`, passes it with length 4 at `0x420ab65`.
- The `&str` list at `0x6483c68` holds `C`, `Cross`, `I`, `Isolated`. Four users (`0x41fe720`, `0x41fe840`, `0x3f7a920`, `0x3fb7ab0`) pass it with length 4.
- The message `enum Leverage` (`0x7c841c`, 13 bytes) is loaded with `edx = 0xd` in `0x25eb590`, `0x4229220` and `0x5b097d0`.
- Inference: this is a serde enum `Leverage` with variants `Cross` (written `C`) and `Isolated` (written `I`), and fields `leverage` (written `l`) and `raw_usd` (written `u`). Each list holds both names of each entry, so the deserializer accepts either.

## Results and limitations

- Result: field `l` is `Leverage`. Tag 0 is `Cross { leverage: u32 }`, tag 1 is `Isolated { leverage: u32, raw_usd: i64 }`. The default skip from #6224 (tag 0, payload `0x14`) is `{"C": 20}`, so cross leverage 20 is not written.
- Limits:
  - Tag 0 as Cross comes from the name order and the JSON branch; the writers send every tag except 1 to `"C"`.
  - `raw_usd` as a margin amount is a name-based inference; its unit is not mapped.
  - The deserializer bodies and the other users of `"C"` and `"l"` are not read.

## Implementation and comparison

The tool pins 23 instruction byte runs, 29 references, 10 strings, two four-entry `&str` lists, both writers' call censuses and a `lea` census for seven targets. Tests mutate one byte at a time in a copy of the image and expect rejection (9 mutation tests). Alternatives considered: reading the deserializer bodies (bounded out); emulation (not allowed for this repository).
