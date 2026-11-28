# Compare the complete Clearinghouse halted-assets subtree

Compare the full ordered raw ABCI subtree at `[0,1,0,9]` against the named checkpoint field `exchange.locus.cls[].halted_assets`. Relative raw child zero appends each asset identifier as a U64. Relative child one appends one U64 count per Clearinghouse, including zero-length sets. Equal asset IDs in different Clearinghouses remain separate contributions. The counts preserve the partition of the otherwise flat identifier stream.

The field at Clearinghouse `+0x4c8` goes through the named sequence serializer `0x464a630`, which reads the asset identifier as a qword at `0x464a7a1`. The raw Clearinghouse slot uses descriptor `0x648cc78` and visitor `0x450f8a0`. That visitor walks the ordered set and stages qword pointers with descriptor `0x648e380`, then stages the per-set count with descriptor `0x648e1f0`. Its call at `0x450fba1` applies the two streams to `0x41ae280`. Both raw descriptors eventually reach the U64 writer `0x14199b0`.

#6219 names the compact field offset and #7817 maps the parent slot. This comparator adds the complete asset IDs and lengths at that slot. It consumes named arrays in canonical ascending order within each Clearinghouse and requires an independently pinned, same-height raw export. It also validates the reference's entire declared digest.

From repository root with the pinned helpers, Python plus msgpack and rustc:

```sh
python -B research/work-items/RE-009-node115-clearinghouse-halted-assets-root/verify.py --helpers /path/to/helpers --rustc /path/to/rustc
```

The verifier checks the original binary statically and runs a locally compiled BLAKE3 fixture driver. The synthetic tests use three Clearinghouses with uneven sets, repeated IDs across sets, and an ID wider than 32 bits. They cover empty sets, no Clearinghouses, wrong ordering, regrouped lengths and the canonical scope's per-set uniqueness. No network checkpoint or reference root is included.

[Measured offline output](offline-log.txt)
