# RE-008: node #115 per-user value text writer (117th stage): the text is pretty JSON, and a JSON reader exists

- Component ID: abci. Question: open PR #6575 showed that the position writer `0x448ae20` writes text (`M: <decimal>`, entries joined by `,\n`), while the position decoder `0x1bb6b90` of #6453 and #6456 reads MessagePack. What is this text form, which path uses it, and does any decoder read it?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6575, #6456, #6453, #6239 and #6223. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, call targets, string bytes and the direct-call census are observations. "Pretty JSON", "key writer", "JSON reader" and "field matcher" are inferred labels. The binary was not executed.
- Scope included: the key writer `0x4713ba0`, the format choice in `0x422ed40`, the single-caller chain from `0x422ed40` to the per-user value writer `0x3beac00`, the head of the JSON position reader `0x402e7c0`, and its field matcher `0x4455890`. Scope excluded: the two callers of `0x422ed40`, the file write after serialization, the MessagePack serializer `0x3c13960`, and the M rules (zero, default) inside the JSON reader. No gate changes.

## Result

| Part | Address | What it does |
|---|---|---|
| Key writer | `0x4713ba0` | `\n` before the first key, `,\n` before later keys, the indent string `current_indent` times, then the key between `"` bytes through the escaper `0x46708b0` |
| Position keys | `0x448af18`, `0x448af87`, `0x448afff`, `0x448b06d`, `0x448b0f3` | `s`, `l`, `M`, `f`, `e`, each with length 1 |
| Format choice | `0x422ed40` | file extension equal to 3-byte `rmp` (`0x4659e5`): MessagePack serializer `0x3c13960`; any other extension: a 0x80-byte buffer, a pretty formatter with indent `"  "` (`0x7c809e`, 2 bytes), and the JSON serializer `0x3c136f0` |
| Path to the writer | see below | each function has exactly one direct caller |
| JSON reader | `0x402e7c0` | skips whitespace (mask `0x100002600`: space, tab, LF, CR), takes `[` or `{`, calls the field matcher `0x4455890` (its only caller) |
| Field matcher | `0x4455890` | `s`/`szi` 0, `l`/`leverage` 1, `M` 2, `f`/`cum_funding` 3, `e`/`entry_ntl` 4, any other key 5 |

So the text in #6575 is the pretty JSON form of the state, with keys in quotes, for example `"M": 21`. It is written when the output file name does not end in `.rmp`. It is not output-only: a JSON reader for the position exists, and it accepts the same keys and gives the same field indices as the MessagePack matchers `0x183e010` and `0x2d129d0` of #6453.

Path from the format choice to the per-user value writer (callee: only direct caller):

| Callee | Only direct caller | String the caller loads |
|---|---|---|
| `0x3c136f0` | `0x422ed40` | |
| `0x3c2f460` | `0x3c136f0` | |
| `0x3c2e340` | `0x3c2f460` | `locus`, `perp_dexs` (`0x7ba2fa`) |
| `0x4615470` | `0x3c2e340` | |
| `0x4482170` | `0x4615470` | |
| `0x446b620` | `0x4482170` | `user_states` (`0x7d07c9`) |
| `0x4663f30` | `0x446b620` | `user_to_state` (`0x7d1614`) |
| `0x3beac00` | `0x4663f30` | |

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_value_text_writer_115.py --check
python3 -m unittest tests.test_user_value_text_writer_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the key writer

- `0x4713be7`: first key, append byte `0x0a`. `0x4713c0c`: later key, append the word `0x0a2c` (`,\n`).
- `0x4713c21`: `r15 = [rbx+0x18]` (indent count); zero skips the loop. `0x4713c38`: indent pointer `[rbx+0x8]` and the copy slot `0x64df508`; the loop copies the indent `r15` times.
- `0x4713ca6`: state byte set to 2. `0x4713cc9` and `0x4713cec`: append `0x22` (`"`) before and after the key; `0x4713cda`: `call 0x46708b0` writes the key text.

## Evidence 2: the format choice

- `0x422ee28`: `lea rdx,[rip+...]` to `0x4659e5` (`rmp`), `mov ecx,3`, `call 0x159fca0`; `test al,al; je 0x422eeae`.
- `0x422ee82`: `call 0x3c13960` on the `rmp` branch.
- `0x422eeae`: `mov edi,0x80` and an allocation call. `0x422eedd`: indent pointer `0x7c809e`, indent length 2, indent count 0, "has value" false; `0x422ef08`: `call 0x3c136f0`.

## Evidence 3: the JSON reader and its matcher

- `0x402e7ee`: `movabs r13,0x100002600`. `0x402e838`: `cmp esi,0x5b` (`[`) and `cmp esi,0x7b` (`{`). `0x402ea50`: `call 0x4455890`.
- `0x4455890`: key length 1 to 11 through table `0x7ce038` (length 1: `0x44558b0`; 3: `szi`; 8: `leverage`; 9: `entry_ntl`; 11: `cum_funding`; other lengths: index 5).
- `0x44558b0`: a 1-byte key goes through table `0x7ce064` at `byte - 0x4d`: `M` to index 2, `s` 0, `l` 1, `f` 3, `e` 4.

## Implementation and comparison

The tool pins 21 instruction byte runs (each with its meaning). It also checks the three strings, the two `lea` targets and the extension length in `0x422ed40`, the five position key loads, both matcher tables, and a direct-call census over `.text` with function starts from `.eh_frame_hdr`. Tests change bytes in a copy of the image and expect rejection with a named reason. Where a change sits inside a pin, the test removes that pin, so a derived check must catch it. Alternatives considered: running the serializer on a sample state (not allowed for this repository).

## Results and limitations

- Result: the text writer is the pretty JSON form, picked for any output path that does not end in `.rmp`. A JSON reader for the position uses the same keys and field indices as the MessagePack reader. The text form is not output-only.
- Limits: the two callers of `0x422ed40` (`0x2ae41e0`, `0x2cde430`) and the file write after serialization are not mapped. The JSON reader's handling of M (0 rejected, default 20) and the other defaults are not checked; only its key matcher is. A second matcher with the same key set, `0x4455970` (called from `0x32d3c90`), is seen but not mapped. The chain from `0x402e7c0` up to a top-level JSON state reader is not mapped.
