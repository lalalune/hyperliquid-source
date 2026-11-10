# RE-008: node #115 abci_hashes `exchange_abci_hash` JSON shape (54th stage)

- Component ID: abci. Question: the 53rd stage (open PR #6034) found that each `abci_hashes` line carries the hash tree under the key `exchange_abci_hash`, written by the field writer `0x506d4e0` and the node writer `0x5025a10`. It left the exact JSON shape open. The 50th stage (open PR #6030) bound the MessagePack form of the same tree that feeds the root digest.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6030 and #6034. It imports helpers only from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, constants, string bytes and call targets are observations. "JSON", "array", "decimal", "escape" and "hex" are inferred labels from the written bytes and call shapes. The example is derived from the bound writer logic; the binary was not executed.
- Scope included: the field writer `0x506d4e0`, the node writer `0x5025a10` up to the end of its element loop, the leaf writer `0x4e1c250`, and the decimal fast path of `0x50fc010`. Scope excluded: the string escaper `0x50a3510`, the Vec grow path `0x5963a10`, the hex encoder body (#6031), and the record serialiser `0x537d5e0` (#6034). No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_hashes_tree_json_115.py --check
python3 -m unittest tests.test_abci_hashes_tree_json_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the field

`0x506d4e0` writes `,` (`c6 04 01 2c` at `0x506d518`) unless the state byte at `+0x1` is 1 (`0x506d4fe`), sets that byte to 2, then writes `"`, the key through `0x50a3510`, `"` and `:` (`0x506d53b`, `0x506d55f`, `0x506d581`). A value tag of 1 (`0x506d58c`) tail-jumps to the node writer (`0x506d5a9`); any other tag passes value `+0x1` (32 bytes, capacity `0x42`) to the leaf writer (`0x506d5de`).

## Evidence 2: the node

`0x5025a10` writes `[` (`0x5025a3a`). An empty Vec writes `]` at once (`0x5025afa`), so the node is `[]`. Otherwise, for each 0x30-byte element (stride `rbp*3 << 4` at `0x5025ba3`, `add 0x30` at `0x5025cf6`/`0x5025cfa`):

- `,` between elements (`0x5025bd5`), none before the first;
- `[` (`0x5025a5f`, `0x5025bfc`);
- the index at element `+0x0` through `0x50fc010` (`0x5025a72`, `0x5025c10`);
- `,` (`0x5025abf`, `0x5025c65`);
- the child: tag byte element `+0x8` equal to 1 recurses on element `+0x10` (`0x5025add`, `0x5025c81`, the only two calls inside the function); any other tag writes the 32 bytes at element `+0x9` (`0x5025b28`, `0x5025cae`) through the leaf writer;
- `]` (`0x5025b61`, `0x5025ceb`).

The node then ends with `]` (`0x5025b87` and the shared tail).

## Evidence 3: index and leaf

- Index: `0x50fc010` fills a 20-byte buffer (`mov eax, 0x14`) from the right with two-digit pairs from `0x91b2fc` (`000102…`), dividing by 10000 with the multiplier `0x346dc5d63886594b`. Inference: unsigned decimal, no sign, no padding.
- Leaf: `0x4e1c250` hex-encodes through slot `0x64e4d08` with trim byte 0 (`xor r8d, r8d`), then writes `"`, the string through `0x50a3510`, and `"`. A zero-length input writes the 2-byte literal `0x` at `0x918564` instead. With 32 bytes the string is `0x` plus 64 lowercase hex digits (#6031).

No instruction in these writers writes a space or a newline between tokens.

## Derived example

Children `(0, leaf 00..1f)` and `(3, leaf 20..3f)`, the same tree as #6030:

```
[[0,"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"],[3,"0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"]]
```

147 bytes. The structure matches the MessagePack form in #6030: an array of `[index, child]` pairs with `0x`-hex leaf strings. Only the encoding differs.

## Implementation and comparison

The tool pins 46 instruction byte runs and 13 call or RIP-relative targets, checks the two string constants and the two recursion sites, and renders the example with the decoded rules. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternative considered: running the node to capture a real line (not allowed for this repository).

## Results and limitations

- Result: `exchange_abci_hash` is compact JSON: `[` `[index,child]` … `]`, decimal indices, leaves `"0x…"`, nested nodes as nested arrays, `[]` for an empty node.
- Limits: the escaper `0x50a3510` is assumed to pass hex digits unchanged (they need no escaping in JSON) but its body is not bound. The decimal path above 10^8 and the overflow branches of `0x50fc010` are not bound. Whether a node can be empty at runtime is not shown.
- Next lead: none in this tree; the abci digest series (#6023 to #6034) is complete through the root and both logs.
