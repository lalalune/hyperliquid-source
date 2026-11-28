# RE-009 · Preserve child ordinals through the node #115 Locus root worker

The grouped Locus root visitor sets up 16 source slices and 16 destination children. The selected dispatcher splits both arrays at the same ordinal, using each array's own stride. This keeps checkpoint root-field ordinals stable when the group is subdivided. A child result other than status 4 stops the selected serial worker and marks the shared stop byte.

| Boundary | Native evidence |
| --- | --- |
| Locus handoff | `0x3d2a499` and `0x3d2a4f4` pin both lengths to 16. `0x3d2a4e3` clears the shared stop byte. `0x3d2a515` enters launcher `0x3ddbda0`. |
| Dispatch | The launcher preserves destination and source bases and lengths in a four-word row and calls `0x3ebe3f0` at `0x3ddbe23`. The dispatcher checks the shared stop byte before any child visit. |
| Split | With `m = count / 2` rounded down, the destination suffix starts at `destination + 24*m`, and the source-slice suffix starts at `source + 16*m`. The lengths are reduced by the same `m`. The split scheduler is entered at `0x3ebe5de`. For 16 children the two suffix pointers jump by `0xc0` and `0x80`. |
| Selected serial route | When no further split is selected, `0x3ebe48b` enters `0x457ccb0` with paired cursor bounds. The worker advances 24 bytes per destination and 16 per source slice. |
| Child write | A destination starting with `0x8000000000000001` uses constructor `+0x20` before the visit at descriptor `+0x18`. The destination is reused on the non-sentinel route. |
| Stop and return | A non-4 visitor return reaches `0x457cda2` and the stop store at `0x457cdd7`. The selected serial call returns the child status through its result record. A later dispatcher entry with the stop byte already set returns 4 without visiting a child. That shortcut does not establish that the skipped children were written. |

The [capture-slot packet](../RE-008-abci-hash-slots-115/README.md) maps the top-level compact root slots. [#7344](https://github.com/lalalune/hyperliquid-source/pull/7344) maps each Locus field to one ordered source slice and stops at the grouped dispatch boundary. [#7352](https://github.com/lalalune/hyperliquid-source/pull/7352) reconstructs the nested Context subtree. This packet validates the grouped Locus handoff and selected worker behavior. A runtime scheduler trace, the body of every child visitor, and any real H/H+1 values remain open.

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From repository root, with the pinned artifact present:

```sh
python3 -B research/work-items/RE-009-node115-locus-root-worker-order/verify.py
```

The verifier checks the authenticated [disassembly windows](windows.txt), recomputes selected transfer destinations and runs an offline model for a 16-child split, shorter and odd counts, construction and reuse, and the stop paths. The model checks selected address geometry and status transitions using symbolic records. [Measured offline output](offline-log.txt).
