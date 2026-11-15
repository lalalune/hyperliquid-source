# RE-008: node #115 abci hash tree byte encoding (fiftieth stage)

- Component ID: abci. Question: #6029 found that the root step `0x41c5140` serialises the slot tree (#6027) and hashes the bytes with BLAKE3 (#6024). It left open the exact bytes that go into that hash.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6024, #6027 and #6029. It imports helpers only from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, call targets, relocations, the hex table and call censuses are observations. "MessagePack", "array", "uint", "string" and "fixint" are inferred labels from the marker values. The worked example is derived from the bound rules; the binary was not executed.
- Scope included: the root serializer set-up, the node encoder `0x41444a0`, the element encoder `0x41c7780`, the array header `0x3d50270` and marker `0x3d52310`, the uint writer `0x3d517e0`, the string header `0x41c6110` and the hex encoder `0x2eabb50`. Scope excluded: the unknown-length path of `0x41444a0` (taken only for 2^32 or more elements), the `0xda`/`0xdb` string branches, and what config byte `+0xc == 2` selects. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_hash_tree_encoding_115.py --check
python3 -m unittest tests.test_abci_hash_tree_encoding_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only.

## Evidence 1: root

`0x41c5140` builds the serializer state: a Vec, the dword `0x400` at `+0x8` (`0x41c5185`) and the byte 0 at `+0xc` (`0x41c518d`). It compares the root tag byte with 1 (`0x41c5192`). Tag 1 passes the node at `+0x8` to `0x41444a0` (`0x41c51a5`). Any other tag hex-encodes the 32 bytes at `+0x1` (`esi = 0x42`, `ecx = 0x20`, `r8d = 0`, slot `0x64e4d08`) and writes them through `0x41c6110`.

## Evidence 2: node and element

- `0x41444a0` reads the Vec pointer `[rdx+0x8]` and length `[rdx+0x10]`, writes an array header of that length through `0x3d50270` (`0x4144506`), then calls `0x41c7780` for each 0x30-byte element (`lea rax,[r14+r14*2]; shl rax,4`; `add r15,0x30`).
- `0x41c7780` compares config byte `+0xc` with 2. With the root's 0, it writes an array header of 2 (`mov edx,2`, `0x41c7805`), the u64 index at element `+0x0` through `0x41d2670` → `0x3d517e0`, then the child. A child tag byte (`+0x8`) other than 0 recurses into `0x41444a0` with the Vec at `+0x10` (`0x41c7893`). Tag 0 hex-encodes the 32 bytes at `+0x9` and writes the string (`0x41c7a45`).

## Evidence 3: markers

| Writer | Rule |
|---|---|
| array `0x3d50270`/`0x3d52310` | len < 0x10: `0x90 \| len`; len < 0x10000: `0xdc` + u16; else `0xdd` + u32 |
| uint `0x3d517e0` | < 0x80: the byte itself; < 0x100: `0xcc`; < 0x10000: `0xcd`; < 2^32: `0xce`; else `0xcf` |
| string `0x41c6110` | len < 0x20: `0xa0 \| len`; len < 0x100: `0xd9` + u8 |
| hex `0x2eabb50` | writes `0x` (word `0x7830`), then two digits per byte from table `0x455d40` = `0123456789abcdef` |

Both hex callers pass 66 output bytes, 32 input bytes and no leading-zero trim, so every leaf is `0xd9 0x42 "0x"` + 64 lowercase hex digits (68 bytes). Slot indexes 0..58 (#6027) are single bytes.

## Evidence 4: derived example

For a node with children `(0, leaf 00..1f)` and `(3, leaf 20..3f)`, the rules give 141 bytes:

```
92                      node: 2 elements
92 00 d9 42 30 78 ...   element: [0, "0x0001…1f"]  (70 bytes)
92 03 d9 42 30 78 ...   element: [3, "0x2021…3f"]  (70 bytes)
```

The root digest is BLAKE3 of these bytes (#6024, #6029). Empty slots are not in the Vec (#6029), so their indexes are absent.

## Results and limitations

- Result: the hashed bytes are a MessagePack array tree of `[index, child]` pairs. Leaves are 66-character `0x` hex strings of the slot BLAKE3 digests.
- Limits: config byte `+0xc == 2` (no pair header) and the unknown-length node path are not mapped; they are not taken with the root's config. The `0xda`/`0xdb` string headers are not pinned.
- Next lead: other callers of the hex slot `0x64e4d08`, to see whether the same `0x` string form is used for digests outside the abci hash.
