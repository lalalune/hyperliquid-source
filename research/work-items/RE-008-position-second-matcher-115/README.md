# RE-008: node #115 second position key matcher (119th stage): a second MessagePack position decoder

- Component ID: abci. Question: open PR #6579 found that `0x4455970` has the same key compares as the JSON position matcher `0x4455890`, with success tag 9 instead of 0, and named its one caller `0x32d3c90` without mapping it. What reads keys through `0x4455970`, what does it do with each field index, and does it use the same M rules (0 rejected, missing M is 20)?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6579, #6456 and #6453. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, relocation values and strings are observations. "MessagePack", "success tag", "not seen", "default", "duplicate" and the field names are inferred labels. The binary was not executed.
- Scope included: the two matchers compared byte by byte, the key path of `0x32d3c90`, its field table, the s, e and M arms, the M value read down to the integer slot, the end-of-map defaults for M and l, and the two direct callers. Scope excluded: the bodies of the l, f and skip readers, the integer read `0x34861d0` (mapped in #6456), the sequence (array) form, where the decoded fields are stored, and the callers above `0x318126c` and `0x372f3ae`. No gate changes.

## Result

| Question | Answer |
|---|---|
| What is `0x4455970`? | The same key matcher as `0x4455890`, built for a second result type. 0xd4 bytes; they differ only in two jump-table `lea` displacements and six success-tag bytes (0 vs 9). Both table pairs send each key to the same function offset. |
| Who calls it? | `0x32d3c90`, for map keys that pass slot `0x64dfca8` (result tag not 1). Keys with tag 1 go to `0x2fc4d70`. |
| What is `0x32d3c90`? | A position decoder over MessagePack markers (fixmap `0x80`, fixarray `0x90`, fixstr `0xa0`, others from `0xc0`). Every callee result is tested with `cmp al,9`, so 9 is its success tag. |
| Field indices | 0 s (reader name `Szi`), 1 l, 2 M, 3 f, 4 e (reader name `Ntl`), 5 skip. Same as #6453 and #6579. Duplicate-field names `s`, `l`, `M`, `f`, `e`. |
| M = 0 | Read through slot `0x64e25d8`, relocated to `0x34861d0`: the same integer read #6456 found for the first MessagePack decoder, which rejects 0 as `a nonzero u32`. |
| M missing | 0 means "not seen"; at the end of the map it becomes 0x14 (20). |
| l missing | Tag 0 with 0x14, as in #6453. |

So the binary has two MessagePack position decoders and one JSON reader. All three use the same field indices and the same M rules.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/position_second_matcher_115.py --check
python3 -m unittest tests.test_position_second_matcher_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eight `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the two matchers

- `0x4455890` and `0x4455970` are each 0xd4 bytes. Byte by byte they differ at matcher offsets `0x13` and `0x32` (displacements of `lea rcx,[rip+...]` and `lea rdx,[rip+...]` to their own jump tables) and at six `mov byte [rax],imm8` sites: `0` in `0x4455890`, `9` in `0x4455970`.
- The first table pair (`0x7ce038`, `0x7ce100`, 11 entries, by key length) and the second pair (`0x7ce064`, `0x7ce12c`, 0x27 entries, by first byte) give the same offset from the function start for every entry.

## Evidence 2: key path and field dispatch in `0x32d3c90`

- `0x32d42fc`: `call [0x64dfca8]` on the key bytes (slot relocated to `0x16815e0`). `cmp dword [rsp+0xb0],1; jne 0x32d4330`. Tag 1 calls `0x2fc4d70` (`0x32d4315`); otherwise `0x32d4346` calls `0x4455970`.
- `0x32d3f4a`: `cmp al,9; jne` error; `movzx eax,byte [rsp+0x51]`, then a jump through `r12`. `r12` is loaded with the table `0x722690` (`0x32d438f`).
- The six table entries are `0x32d3f65` (s), `0x32d4097` (l), `0x32d4007` (M), `0x32d4036` (f), `0x32d3fb6` (e) and `0x32d3e80` (skip one value with `0x31d5e50`).
- Each field arm jumps to a duplicate-field `lea` of its own 1-byte name: `s` `0x32d50b0`, `e` `0x32d50b9`, `f` `0x32d50c2`, `M` `0x32d50cb`, `l` `0x32d50d4`.
- The s arm reads with `0x2f6d9d0` and the name `Szi` (`0x7c8b60`, 3); the e arm with `0x2f65340` and `Ntl` (`0x7db4bb`, 3).

## Evidence 3: M

- M arm (`0x32d4007`): `cmp dword [rsp+0x48],0; jne 0x32d50cb` (duplicate `M`). Then `call 0x4483100`; on tag 9 the 4-byte value goes to `rsp+0x48`.
- `0x4483100` loads the name `MarginTableId` (`0x7d251f`, 13) and jumps to `0x2f6e330`.
- `0x2f6e45d` in `0x2f6e330`: `call [0x64e25d8]`; on tag 9 it keeps the u32. The slot is relocated to `0x34861d0`, the integer read in #6456.
- End of map (`0x32d4c4f`): `mov ecx,0x14`; `cmp ebp,2` (l not seen) gives `r11d = 0x14` and `ebp = 0`; `test r14d,r14d; cmove r14d,ecx` gives M = 20 when it is still 0.

## Evidence 4: callers

- `0x32d3c90` has two direct callers: `0x318126c` and `0x372f3ae`. Before `0x372f3ae`, `0x372f38b` reads a key through `0x2f48380` with the name `Perp` (`0x45a0d0`), as a map from perp to position would.

## Implementation and comparison

The tool pins 12 instruction byte runs (each with its meaning). It also checks the matcher comparison with both jump-table pairs, the six field-table entries, 15 call and branch targets, two slot calls and their relocations, and ten `lea` targets with nine strings. Tests change bytes in a copy of the image and expect rejection with a named reason. Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternative considered: decoding a sample MessagePack position with M = 0 by running the code (not allowed for this repository).

## Results and limitations

- Result: the second matcher belongs to a second MessagePack position decoder. It uses the same field indices, the same integer read for M (0 rejected) and the same defaults (M 20; l tag 0 with 20).
- Limits: which reader type each decoder is built for, and why there are two, is not shown. The slot `0x64dfca8` target `0x16815e0` is not read; that it checks UTF-8 is an inference. The l, f and skip readers, the sequence form, the store offsets of the decoded position and the callers above `0x318126c` and `0x372f3ae` are not mapped.
