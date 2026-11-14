# RE-008: node #115 position field M (116th stage): the value encoder writes the u32 as decimal text

- Component ID: abci. Question: open PR #6456 showed that the position decoder rejects M = 0 and that the position writer `0x448ae20` leaves out M = 20. It did not read the value encoder `0x4648d30` that the writer calls for any other M. Does that encoder write the 4-byte M unchanged?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6456, #6453 and #6224. It does not depend on their files.
- Claim status: instruction bytes, call targets, the relocation and its symbol name, the key string and the digit table are observations. "Entry start", "separator" and "decimal formatter" are inferred labels. The binary was not executed.
- Scope included: the writer M call site, the value encoder `0x4648d30`, the first part of the entry-start writer `0x4713ba0`, and the number formatter `0x46ef430`. Scope excluded: how `0x4713ba0` writes the key itself, the buffer growth path `0x43bd910`, the other position fields, and any decoder for this text form. No gate changes.

## Result

| Step | Address | What it does |
|---|---|---|
| Writer M site | `0x448affb` | `rcx = position + 0x38` (M), key `M` (`0x7d13c1`), length 1, `call 0x4648d30` |
| Entry start | `0x4713ba0` (called at `0x4648d41`) | appends `\n` for the first entry, `,\n` for a later entry |
| Encoder | `0x4648d64` | appends `: `, loads the 4-byte value (`mov edi,[rbx]`), `call 0x46ef430` |
| Formatter | `0x46ef430` | writes the u32 as decimal ASCII digits into a 10-byte buffer and returns start and length |
| Copy | `0x4648da8` | copies the digits through GOT slot `0x64df508`, bound to `memcpy` |

So M is written as its full unsigned decimal text after `M` and `: `. The formatter takes all 32 bits, and its 10-byte buffer holds the largest u32 (4294967295, 10 digits). No digit is dropped and the value is not changed. This closes the limit stated in #6456.

One correction to the reading of #6456: this writer makes text (`,\n` and `: ` separators, decimal digits). The position decoder `0x1bb6b90` that #6453 and #6456 mapped reads MessagePack markers. The writer and that decoder share the field rules (key `M`, default 20, 0 rejected), but they do not share one encoding. So "read back" in #6456 means "the same field rules apply", not "the writer's bytes go into that decoder".

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/position_m_encoder_115.py --check
python3 -m unittest tests.test_position_m_encoder_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the writer passes M to the encoder

- `0x448affb`: `lea rcx,[rbx+0x38]`; `lea rsi,[rip+...]` to `0x7d13c1` (`M`); `lea rdi,[rsp+0x10]`; `mov edx,1`; `call 0x4648d30`; `test rax,rax`.

## Evidence 2: the encoder

- `0x4648d3b`: `mov rbx,rcx` keeps the value pointer, then `call 0x4713ba0`.
- `0x4713ba0` appends `0x0a` (`\n`, at `0x4713be7`) on the first entry and the word `0x0a2c` (`,\n`, at `0x4713c0c`) on a later entry.
- `0x4648d68`: `mov word [rax+rsi],0x203a` appends `: `.
- `0x4648d76`: `mov edi,[rbx]` loads 4 bytes; `0x4648d7f`: `call 0x46ef430`.
- `0x4648da8`: `call [rip+...]` through `0x64df508`. That slot has an `R_X86_64_GLOB_DAT` relocation to the dynamic symbol `memcpy`.
- `0x4648db5`: `mov byte [r12+0x20],1`; `xor eax,eax`; return 0.

## Evidence 3: the formatter is a decimal u32 formatter

- `0x46ef431`: `mov eax,10` (buffer end); `cmp edi,10000; jb` skips the 4-digit loop for small values.
- Loop `0x46ef460`: `q = value * 0xd1b71759 >> 45` (division by 10000); the remainder gives two pairs of digits from the table `0x7d9d8e`; it repeats while the value is above 99999999 (`cmp edi,0x5f5e0ff; ja`).
- The tail writes one more pair if the rest is above 99, one more pair if it is 10 or more, else one digit `rest | 0x30`.
- The table `0x7d9d8e` is the 200 bytes `"00" "01" ... "99"`; three `lea` instructions load it (`0x46ef44c`, `0x46ef515`, `0x46ef532`).
- `0x46ef541`: returns `buffer + start` and length `10 - start`.

## Implementation and comparison

The tool pins 11 instruction byte runs (each with its meaning). It also checks: three call targets, the key load and key text, the separator bytes, the formatter constants (buffer 10, 0xd1b71759 with shift 45, bound 99999999, `0x30`), the three digit-table loads and the table itself, and the GOT slot relocation and its symbol name. Tests change bytes in a copy of the image and expect rejection. Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternatives considered: formatting sample values by running the code (not allowed for this repository).

## Results and limitations

- Result: the writer emits any M other than 20 as `M`, `: `, and the full decimal text of the u32. No value change is found.
- Limits: how `0x4713ba0` writes the key (quotes, indent) is not read; the separators are the only part pinned. The buffer growth call `0x43bd910` is not read. Which decoder reads this text form is not mapped. The label "decimal formatter" is inferred from the constants and the digit table.
