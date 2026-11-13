# RE-008: node #115 abci box layouts that differ by a 0xb70-byte insertion (36th stage)

- Component ID: abci. Question: #6004 found that three `visor_abci_state` writers read the freeze height from box `+0x10e8` while the engine step `0x5a08720` reads it from `+0x1c58`, the field the freeze setter `0x54c9b80` writes (#5970). This packet tests whether the node carries two layouts of the same box.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Imports `read_va` and `direct_calls` from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, constants, FDE extents, call censuses and the byte-level pair classification are observations. "Layout A/B", "box", "freeze setter", "dispatcher" and "output-setter result" are inferred labels. The binary was not executed.
- Scope included: three equal-length function pairs compared byte by byte; the allocation and copy sizes in `0x5a6bfb0` and `0x548ce30`. Scope excluded: what each shifted field holds, the bodies of the 43 paired dispatcher callees, which subcommand uses which layout. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_box_layouts_115.py --check
python3 -m unittest tests.test_abci_box_layouts_115
```

The tool reads the ELF only. The six `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: a sibling freeze setter

`0x54c9a90` and `0x54c9b80` have FDE extents of 0xeb bytes each. Their bytes differ only in five box displacements, each larger by exactly 0xb70 in `0x54c9b80` (`+0x10e8`/`+0x10f0` there, `+0x1c58`/`+0x1c60` here), and six RIP-relative fields that name the same absolute addresses (the shared Once cell `0x64f01d8`). Both add 50000 to the current height before the range check. `0x54c9a90` has one direct call, `0x538e830` in dispatcher `0x538cd30`; `0x54c9b80` has one, `0x5399650` in dispatcher `0x5397b50` (#5970).

## Evidence 2: pairwise classification

The tool reads each differing 4-byte field in both copies and classifies it:

| Pair | Bytes | Shifted by 0xb70 | Same absolute target | Paired functions | Paired tables | Unexplained bytes |
|---|---|---|---|---|---|---|
| setters `0x54c9a90` / `0x54c9b80` | 0xeb | 5 | 6 | 0 | 0 | 0 |
| steps `0x5a07ec0` / `0x5a08720` | 0x85c | 9 | 64 | 3 | 0 | 0 |
| dispatchers `0x538cd30` / `0x5397b50` | 0xae1d | 175 | 476 | 43 | 6 | 4 |

- The step pair shifts box offsets `0xb9a`, `0x10e8`, `0x10f0`, `0x2c20`, `0x39c8`. Its three paired callees include `0x5485a60` / `0x5485f80` (the linked abci state step of #5999).
- The 4 unexplained dispatcher bytes are the immediates of two `add reg, imm32`: `0xb9b` in `0x538cd30` (`0x5395f86`, `0x5396821`) and `0x7c0` in `0x5397b50` (`0x53a0da6`, `0x53a1641`). They are pinned, not explained.
- Across the three pairs, 110 distinct shifted offsets range from `0x7c0` to `0x42af`; none is below `0x7c0`.

## Evidence 3: the two box sizes and the insertion

- `0x5a6bfb0` allocates `0x42c8` bytes (`0x5a6c05d`), copies a `0x42c8`-byte box into it, copies a `0xb70`-byte value (`0x5a6c096`), and calls `0x548ce30` with both.
- `0x548ce30` copies the `0xb70`-byte argument to `rsp+0x7e0` (`0x548d6f5`), which is `+0x7c0` of the image it builds at `rsp+0x20`; copies `0x1700` bytes of that image onward (`0x548d708`); allocates `0x4e38` bytes (`0x548d82f`); and frees `0x42c8` bytes (`0x548d858`).
- `0x4e38 - 0x42c8 = 0xb70`.

Inference: layout B is layout A with a `0xb70`-byte value inserted at `+0x7c0`. #5908 maps that value as the output-setter result. Code built for layout A (`0x54c9a90`, `0x5a07ec0`, `0x538cd30`) reads the freeze height at `+0x10e8`; code built for layout B reads it at `+0x1c58`.

## Implementation and comparison

The tool pins 20 instruction byte runs, 2 allocation calls, FDE extents of the six functions, the classification counts per pair and the four unexplained bytes, then recomputes the shifted-offset range and five call censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). An objdump-text diff gave the same counts for the step and dispatcher pairs.

## Results and limitations

- Result: the node holds two builds of the setter, step and dispatcher for two box layouts that differ by a `0xb70`-byte insertion at `+0x7c0`.
- Limits: the classifier assumes a rel32 or RIP field ends its instruction; it does not decode instructions. The `0xb9b` / `0x7c0` immediates are not explained. `0x5a6bfb0` also calls `0x5a08f80`, which calls the layout-A step `0x5a07ec0`; that path is not mapped. Which subcommand reaches each layout (#5902, #5908) is not mapped.
- Next lead: the path from `0x5a6bfb0` through `0x5a08f80` to the layout-A step.
