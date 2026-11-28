# Compare the complete Clearinghouse PerpMeta universe subtree

Compare named checkpoint `exchange.locus.cls[].meta.universe` against the complete ordered raw ABCI subtree at `[0,1,0,0,0]`. Each Clearinghouse contributes an ordered universe length to relative slot `[1]`. Individual asset fields concatenate across rows under relative slot `[0]`, with four ordered streams. The length stream distinguishes two checkpoints with the same flattened assets divided into different universes.

| Relative path | Preimage |
| --- | --- |
| `[0,0]` | `szDecimals` as one byte per asset |
| `[0,1]` | `name` as U64 byte length followed by exact UTF-8 bytes per asset |
| `[0,2]` | `marginTableId` as little-endian U32 per asset |
| `[0,3]` | `marginMode` as little-endian U64 codes 0, 1, 2 for the three native names |
| `[1]` | U64 number of assets for each Clearinghouse, including empty universes |

The PerpMeta descriptor at `0x6478288` leads to `0x3d6af40`. It walks 32-byte rows, builds the repeated data/descriptor pairs and calls `0x41ae280`, which accumulates all elements into child zero and each input vector length into child one. Its asset visitor `0x44f5dc0` takes field offsets `+0x1d`, `+0x0`, `+0x18`, and `+0x1c`. The raw paths reach byte writer `0x1419620`, UTF-8 writer `0x141a8c0`, U32 writer `0x141b470`, and margin-mode visitor `0x3d1dc20`. The mode visitor widens its byte tag before calling U64 writer `0x14199b0`.

#7817 identifies the Clearinghouse and PerpMeta topology. #7823 compares sibling PDI, collateral token and collateral name streams. This packet covers the separate universe sequence and all four of its asset fields. It verifies a separately pinned raw export's full stated digest and both inputs' heights before comparing the selected subtree. Its scope is complete named asset records whose four fields are present.

From the checkout root with the pinned earlier helpers, Python plus msgpack, and rustc:

```sh
python -B research/work-items/RE-009-node115-clearinghouse-universe-root/verify.py --helpers /path/to/helpers --rustc /path/to/rustc
```

The verifier reads the original artifact as static bytes and executes only a locally compiled BLAKE3 fixture driver. Independent synthetic references cover mixed population, regrouped counts, wrong margin-mode order, incorrect U32 width, and both kinds of empty sequences. A real checkpoint, block, and reference root were outside this fixture set.

[Measured offline output](offline-log.txt)
