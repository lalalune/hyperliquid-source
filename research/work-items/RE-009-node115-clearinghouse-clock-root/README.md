# Compare both Clearinghouse checkpoint clocks with raw ABCI

Compare the ordinary named `exchange.locus.cls[].last_set_global_time` and `lnsgt` clock streams against a separately pinned ordered raw export. The two shared streams occupy `[0,1,0,12]` and `[0,1,0,13]` in the raw tree. The comparator preserves the source row order, checks the separate collection count and ties the checkpoint and raw tree to the same inner Context height.

The named writer calls the same clock serializer `0x4658bf0` for `+0x4f0` and `+0x4fc` at `0x44824af` and `0x44824dd`. The raw Clearinghouse visitor stages those same offsets and reuses descriptor `0x648c850` for both. Its target `0x3d5e950` reaches Time writer `0x141b1e0`, the same canonical encoder established for Context. The writer appends eight bytes for the signed epoch second and four for the fractional nanosecond count. A complete row adds one twelve-byte preimage to each stream, in the row order verified by #7817. Named input uses the same canonical text reader as #7796.

From the repository root with the pinned helper packets, Python plus msgpack, and rustc:

```sh
python -B research/work-items/RE-009-node115-clearinghouse-clock-root/verify.py --helpers /path/to/helpers --rustc /path/to/rustc
```

The verifier statically checks the captured binary and executes only a locally compiled BLAKE3 fixture driver. It builds separately encoded synthetic raw references for empty and populated checkpoints, including a pre-epoch timestamp and nanosecond precision. It changes row order for the first stream and fractional scaling for the second, checking independent mismatch reporting. No real checkpoint or replay root was supplied.

[Measured offline output](offline-log.txt)
