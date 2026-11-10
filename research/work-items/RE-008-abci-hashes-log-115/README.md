# RE-008: node #115 `abci_hashes` line record (53rd stage)

- Component ID: abci. Question: #6033 found that the engine builder creates an `abci_hashes` line writer at engine value `+0x330`, and #6024 found that the digest step passes that value to `0x4e3a7a0`. What does each `abci_hashes` line hold?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #6023 to #6033. It imports helpers from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, strings, relocations, FDE extents and call censuses are observations. "Line", "record", "height", "root digest", "hash tree", "node", "leaf" and "JSON" are inferred labels from the call shapes, strings and earlier packets. The binary was not executed.
- Scope included: the two calls of `0x4e3a7a0` and the record each builds; `0x4e3a7a0`'s calls and flush gate; the record serialiser `0x537d5e0`; the field writers `0x5073b20` and `0x506d4e0`; the entry and recursion of the node writer `0x5025a10`. Scope excluded: the bodies of `0x5077210`, `0x50fc010`, `0x14c37f0`, the rotation sink and the hex encoder (#6031); the full node writer; how the hash tree is built (#6027 to #6029). No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_hashes_log_115.py --check
python3 -m unittest tests.test_abci_hashes_log_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: two writers of the line, one per digest step

`0x4e3a7a0` has exactly two direct calls: `0x548d9e9` in the layout-B digest step `0x548d8c0` and `0x548dbf9` in the layout-A digest step `0x548dad0` (#6024). Both run only when a digest is computed (#6023). Both build the same 0x28-byte record at `rsp+0x48` with identical bytes:

| Record | Source |
|---|---|
| `+0x0` | `r12`, the hash tree the step passed to the root hash (slot `0x64e7820` → `0x41c5140`, #6029) |
| `+0x8` | box `+0x28` (height) |
| `+0x10..+0x30` | the 32 bytes at `rdi`, the root digest |

The time argument is the wall clock (slot `0x64e0990` → `0x1629690`); the writer is the step's third argument (engine value `+0x330` per #6024 and #6033).

## Evidence 2: the line function

`0x4e3a7a0` calls the rotation sink (slot `0x64e0f80` → `0x1546570`) and the liner open (slot `0x64e0020` → `0x14c3b30`), then the serialiser `0x50e5fc0` (its only call). That serialiser calls the record serialiser `0x537d5e0` (its only call), appends `\n` (`0x50e60bb`) and writes through `0x14c37f0`. The extra flush runs only when writer `+0xaa` and the byte behind slot `0x64e0f88` (`0x64ffe50`) are both set.

## Evidence 3: the record

`0x537d5e0` writes `{`, then three fields, then `}`:

| Order | Name (string) | Value |
|---|---|---|
| 1 | `height` (`0x924ed9`, 6) | record `+0x8` |
| 2 | `abci_digest` (`0x924edf`, 11) | record `+0x10`, through `0x5073b20` → `0x4e1c250`, capacity 0x42, length 0x20 |
| 3 | `exchange_abci_hash` (`0x924eea`, 18) | record `+0x0`, through `0x506d4e0` (its only call) |

`0x506d4e0` reads the tree's tag byte. Tag 1 tail-jumps to the node writer `0x5025a10`, which writes `[` and calls itself (`0x5025add`) for nested nodes. Any other tag writes the 32 leaf bytes at `+0x1` through `0x4e1c250` with capacity 0x42 and length 0x20; the node writer uses the same leaf shape (`0x5025b31`). So each line is, by inference:

```
{"height":<u64>,"abci_digest":"0x<64 hex>","exchange_abci_hash":<tree as nested JSON arrays, leaves "0x<64 hex>">}
```

The tree carries child indices and leaf digests (#6029, #6030), not slot names; no field-name strings for the 59 slots appear on this path.

## Implementation and comparison

The tool pins 18 instruction byte runs (including the 0x32-byte record build in both steps), 23 references, 6 relocations and 3 strings, and checks four call censuses. Tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: every digest computation writes one `abci_hashes` line holding the height, the root digest and the whole hash tree.
- Limits: the integer writer `0x5077210`, the index writer `0x50fc010` and the rest of the node writer are named by role only; the exact JSON shape of a node element is inferred from the `[`/`,`/`]` stores and #6030's MessagePack shape, not traced byte for byte.
- Next lead: the node writer `0x5025a10` in full, to pin each element's JSON shape.
