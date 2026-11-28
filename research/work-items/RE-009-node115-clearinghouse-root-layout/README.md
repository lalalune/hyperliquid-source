# RE-009 #115 Clearinghouse raw root slot layout

The named checkpoint `exchange.locus.cls` is a sequence of Clearinghouse records. In the ordered raw ABCI tree, its rows contribute to **one shared field subtree** at `[0,1,0]`, not a nested subtree keyed by the row index. The separate row-count digest is at `[0,1,1]`, including when the sequence is empty. [root-layout.tsv](root-layout.tsv) maps each of the 19 Clearinghouse fields and the five PerpMeta fields to an ordered raw path so a mismatch in this subtree can be traced to its named source.

The existing named-layout packet `RE-008-clearinghouse-fields-115` identifies row offsets. This packet connects those offsets to the raw slots. The result pipeline keeps named serialization and raw aggregation as distinct steps. In particular, the raw visitor appends one Boolean byte per clearinghouse, in sequence order, into the same `perform_auto_deleveraging` leaf `[0,1,0,5]`.

## Native evidence

- The Locus slot-1 descriptor dispatches to `0x43cfeb0`, which tail-jumps to `0x3d67690`. That visitor loads its length from `+0x10` and its row buffer from `+0x8`. At `0x3d67715..0x3d6772d` it creates one data/descriptor pair per row, using a `0x510`-byte source stride and the same descriptor `0x647a010`. The two-lane dispatcher `0x41ae280` applies every row to the same first destination at `0x41ae2ea`, then writes the original count via the qword descriptor `0x6479f20` to the second destination at `0x41ae36d`.
- The row descriptor invokes `0x4504270`, which stages the 19 field pointers and their descriptors in 16-byte pairs from `0x4504281` through `0x450446b`. The writer checks for 19 destinations and advances by 24 bytes per raw child at `0x4504747`. PerpMeta dispatches to `0x3d1c950`, which stages its five source pointers from `0x3d1c95a` through `0x3d1c9ba`.
- For the flag, the named field at row `+0x508` goes through the Boolean serializer call at `0x4482399`. The raw slot's descriptor `0x64884f8` calls `0x1419d40`, which loads and appends one byte.

## Reproduce

From the checkout root with Python, msgpack 1.1.2, the pinned prior helper packets, and a Rust compiler, run:

```sh
python -B research/work-items/RE-009-node115-clearinghouse-root-layout/verify.py --helpers /path/to/pinned/helpers --rustc /path/to/rustc
```

The code reads the captured artifact as bytes. Only the local BLAKE3 hash fixture driver is compiled and executed. The verifier checks the generated table and compares synthetic empty and two-row named checkpoints against separately assembled raw exports. The tests change only row order, count, one raw field slot, or inner Context height as applicable. The CLI requires independently pinned checkpoint and ordered raw export bytes and verifies the export's full declared digest before the scoped comparison.

The comparator covers the sequence count, the 19-way field-stream layout, and the ordinary Boolean stream. Other field preimages remain open. No real network checkpoint, replay, or reference root is included.

[Measured offline output](offline-log.txt)
