# RE-008: node #115 l1 hash map at engine value `+0x3e0` (fifty-ninth stage)

- Component ID: abci. Question: open PR #6040 found that both abci steps compute the l1 hash and pass it, with the height, to `0x5a046f0` on engine value `+0x3e0`. It left open what `0x5a046f0` does, who reads `+0x3e0`, and where the step's other stack value goes.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6023 (digest check) and #6040. Imports helpers from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, constants, relocations, strings, Location records, FDE extents and direct-call censuses are observations. "Map", "insert", "split", "drop", "B-tree", "ring", "running maximum" and "keeps the newest entries" are inferred labels from call shapes and layout. The binary was not executed.
- Scope included: `0x5a046f0`, the matching shape of the digest insert `0x5a03fa0`, the two step call sites, the `visor_abci_state` write just before them, the `+0x3e0` prune in both step wrappers, and the drop glue's read. Scope excluded: the bodies of `0x4dce8b0`, `0x4de4a60`, `0x4e2a4e0`, `0x514dc20`, `0x5248d30`, `0x51e06d0`, and what the 0x68-byte entries are. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/l1_hash_map_115.py --check
python3 -m unittest tests.test_l1_hash_map_115
```

The tool reads the ELF. It does not execute the binary and does not start objdump or readelf. The six `*.objdump.txt` files were made with GNU objdump 2.42 for review only.

## Evidence 1: `0x5a046f0` inserts, then trims to the newest entries

- It calls `0x4dce8b0` (`0x5a04708`, the only direct call to that function) with the map, the key and the value pointer.
- It loads the length at map `+0x18` and returns when it is below `0x33` (`cmp rdx, 0x33` at `0x5a04711`).
- Otherwise it walks back from the newest entry: its extent holds 43 calls to `0x4e2a4e0` and 7 to `0x514dc20`, 50 in all. Entries are 0x28 bytes (`lea rsi, [rax+rax*4]` after `shl rax, 3`).
- It splits the map at the key it reaches (`0x4de4a60` at `0x5a04d9a`), drops the older part (B-tree: `0x5248d30` at `0x5a04dab`; ring: deallocate len × 0x28 at `0x5a04e04`) and moves the newer part back into the map.
- The digest insert `0x5a03fa0` (#6023) has the same shape: insert `0x4dd45c0`, `cmp rdx, 0x33`, 43 calls to `0x4e2a530` plus 7 to `0x514dc20`, split `0x4de5ad0`.

Inference: both maps keep about the newest 51 heights.

## Evidence 2: the step call sites

| Step | Call | Map | Key | Value |
|---|---|---|---|---|
| A `0x5a07ec0` | `0x5a08267` | `lea rdi, [r14+0x3e0]` | `r15` | `rsp+0x180` (the l1 hash output of `0x452aab0`, `0x5a080a9`) |
| B `0x5a08720` | `0x5a08ac7` | `lea rdi, [r14+0x3e0]` | `r15` | `rsp+0x180` |

Each is preceded by a call to the `hyperliquid_data` wrapper `0x5942b40` (`0x5a08250`, `0x5a08ab0`) with the name slice `0x64b7f70` → `visor_abci_state` (16 bytes) and Location `0x64b7f80` → `l1/src/abci/engine.rs:316:46`. The stack value it writes is built from box `+0x10/+0x18`, `+0x28`, the freeze height (A `+0x10e8`, B `+0x1c58`), `+0x60/+0x68`, and the wall clock (slot `0x64e0990` → `0x1629690`): the #6004 `visor_abci_state` value. This answers #6040's open record: the step writes `visor_abci_state.json` on this path.

## Evidence 3: readers of `+0x3e0`

An objdump text census of `[reg+0x3e0]` operands with a non-stack base in the engine code finds five sites, all bound by the tool:

| Site | Function | Use |
|---|---|---|
| `0x5a05833` | wrapper A `0x5a04e40` | prune |
| `0x5a07062` | wrapper B `0x5a06600` | prune |
| `0x5a08255` | step A | insert |
| `0x5a08ab5` | step B | insert |
| `0x5a4c8ac` | drop glue `0x5a4c8a0` | free |

The prune: when engine value byte `+0x0` is set (`0x5a0580d`), the wrapper takes `[+0x8] + 1`, saturating to `u64::MAX` (`0x5a0581d`..`0x5a05827`), splits the map there (`0x5a0584e`), drops the lower part without reading a value (B-tree drop loop `0x51e06d0` at `0x5a05e76`; ring dealloc `0x5a05b11`), and stores the upper part back (`0x5a05e86`..`0x5a05e9d`). `+0x0/+0x8` is a running maximum of key `+0x0` over 0x68-byte entries (`[rsp+0x180]`, length `[rsp+0x188]`), stored at `0x5a0579e`/`0x5a057a2`. The digest map's prune at `+0x10/+0x18` (#6023) follows it.

Inference: no code found compares an l1 entry. Entries leave the map either by the 51-entry trim or when the running maximum passes their height.

## Results and limitations

- Result: `+0x3e0` is a height → l1 map that mirrors the digest map's insert and trim; the step writes `visor_abci_state` before inserting; the wrappers drop l1 entries as a separate 0x68-entry maximum advances.
- Limits: the reader census is an operand-shape search; a reader reaching the map through another base (for example runner `+0x6b0` + `0x3e0`) or a copied engine value is not excluded. What the 0x68-byte entries at `[rsp+0x180]` are, and where they come from, is not mapped (they may come from networking code, which this packet does not enter). The visor write's condition is inherited from #6040's `bpl` branch and not re-proved here.
- Next lead: the source of the 0x68-byte entry slice at wrapper `[rsp+0x180]`, up to the first networking boundary.
