# RE-017: Map verified #115 frames back to original capture fragments

A captured five-byte replay header and its payload can cross file boundaries. This adapter verifies each source fragment and the ordered joined stream independently, then feeds the exact joined bytes to the existing retained-frame fixture. It reports each verified frame's original fragment indices, relative byte offsets and lengths. This preserves capture provenance when assembling complete evidence from independently pinned files. [Existing single-file capture reader](https://github.com/lalalune/hyperliquid-source/pull/7662)

The synthetic capture contains ten plain or LZ4 Block frames across four source fragments. The first frame's header touches three fragments. The second frame's compressed body touches two. The test rebuilds every raw frame from its reported original byte ranges and verifies identical bytes. Nine retained links pass and the first converted record matches the selected synthetic H/H+1 Context references. Controls independently reject wrong fragment order and an incorrect source-fragment digest.

The verifier reuses the exact pinned static and Rust capture check. The Linux x86-64 #115 ELF with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` is read as data. File ordering, original capture provenance, and actual production root provenance remain caller-supplied evidence.

## Reproduce

From the repository root, set `packet` to this directory and use Python with msgpack 1.1.2 and PyCryptodome 3.23.0, Rust 1.95, and the exact pinned snapshots available in local Git.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

For a supplied case, keep the `framed_capture.sha256` for the entire ordered stream and the original `frames` metadata. Replace `framed_capture.path` with a nonempty sorted-by-capture-order `fragments` list, each with relative `path` and original-file `sha256`. The report includes each original fragment's stream interval and the per-frame fragment-relative ranges. See the [raw offline run](offline-log.txt).
