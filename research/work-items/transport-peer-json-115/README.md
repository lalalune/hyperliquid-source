# transport: reconstruct node #115 peer endpoint report JSON writers (Ipv4Addr string, [direction, ip, port] tuple, {n,total,max} statistic object, three sequence writers) and prove them on 14,430 capacity-swept cases

This packet turns a cluster of eight compact serde_json writers of node #115 into an executable Python model and proves the model against the real instruction bytes: for every case the model predicts the exact output bytes, the final `Vec<u8>` capacity and every capacity-growth event (old capacity to new capacity) of the writer, and the bytes run through an offline x86-64 interpreter must agree. A reconstruction can now take the peer endpoint report shapes (`["In"|"Out","a.b.c.d",port]`, `{"n":..,"total":..,"max":..}`, `[[endpoint,f64],..]`, `[[endpoint,u64,u64,f64],..]`, `[["name",{stat}],..]` from a slice-pair or a B-tree iterator), the reserve granularity of each token, the serde_json escape rules and the null rule for non-finite floats from this model instead of guessing them.

- Component ID: transport (Network transport; task: map frame lengths, compression boundaries and error handling without network traffic - this packet covers the report/metrics JSON writers that sit beside the peer rate limiter, not framing)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository commit `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was copied (labels in the reference tree were not used)
- Claim status: observation for every byte-level statement checked by the interpreter; inference for the role names (peer endpoint, statistic); unresolved items are listed under Results and limitations
- Scope included and excluded: functions 0x4772bc0, 0x4781f10, 0x4771750, 0x47775c0, 0x4776de0, 0x4776230 (targets) and their helpers 0x4778320, 0x4779320, 0x4777ad0, 0x47781a0, 0x4774eb0, 0x4787e90 (run as real code). Excluded: the ryu f64 formatter (slot 0x64e13d0, target 0x5d0e4c0, run as a modelled stub), memcpy (slot 0x64df508), the allocator behind 0x4787da0, the callers of the six writers and the pretty-printing member writer 0x4777cc0.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/transport_peer_json_115.py --out research/work-items/transport-peer-json-115
python3 -m unittest tests.test_transport_peer_json_115
```

The tool checks the binary SHA-256 first and fails on a mismatch, never executes the binary, reads only ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, and writes every file of this folder except this README and `MANIFEST.sha256`. It runs about 3.5 minutes and stays under 1.5 GB. Two runs with different hash seeds and time zones give identical bytes. Hashes of all files are in `MANIFEST.sha256`.

## Evidence

All addresses are virtual addresses of the node #115 image; function extents are the `.eh_frame` FDE extents (`functions.tsv`, with the SHA-256 of each byte range, instruction count and the call targets found by the decoder).

| address | size | role (inference from behaviour) |
| --- | --- | --- |
| 0x4772bc0 | 641 | writes `"a.b.c.d"` from four octets: quote, escape-contents of the dotted text, quote |
| 0x4781f10 | 811 | writes `[dir,"ip",port]`: `"Out"` when the flag byte at offset 6 equals 1, else `"In"`; port is the u16 at offset 4, decimal |
| 0x4771750 | 326 | writes `{"n":u64,"total":f64,"max":f64}` |
| 0x47775c0 | 1295 | `[[endpoint,f64],...]` over a Vec of 16-byte rows |
| 0x4776de0 | 2006 | `[[endpoint,u64,u64,f64],...]` over a Vec of 32-byte rows |
| 0x4776230 | 2988 | `[["name",{stat}],...]` over (a) two slices of 48-byte rows (state word 2) or (b) a B-tree range (state word 1, leaf node layout keys at +8, values at +0x110, length u16 at +0x21a, edges at +0x220) |
| 0x4778320 | 552 | serde_json escape-contents writer, table read from the ELF (`escape-table.tsv`: 34 escaped bytes; control bytes use `\u00xx` with lowercase hex) |
| 0x4777ad0 / 0x47781a0 | 492 / 384 | object entry writers; 0x47781a0 writes a comma when the compound state byte is not 1; both set the state byte to 2 |
| 0x4774eb0 | 230 | f64 value: bits above 0x7fefffffffffffff (infinities, NaN) write `null`, otherwise the ryu text |
| 0x4787e90 | 142 | RawVec grow: new capacity = max(2*cap, len+additional, 8) (element size 1) |

Observed reserve granularity (the part a Rust reconstruction must reproduce to give identical capacity growth): single punctuation bytes reserve one byte; escape-contents flushes each unescaped run with one reserve of the run length, a short escape reserves 2, `\u00xx` reserves 6; decimal text is reserved as one block; `null` reserves 4. Worked rows (machine and model agree on each; the tool prints the same kind of row for every case in `cases-sample.tsv`):

| writer | initial cap/len | output | cap after | growth events |
| --- | --- | --- | --- | --- |
| ipv4_string | 0/0 | `"10.0.255.7"` | 16 | 0>8, 8>16 |
| endpoint_tuple | 0/0 | `["Out","10.0.255.7",8000]` | 36 | 0>8, 8>18, 18>36 |
| endpoint_tuple | 20/3 | `xyz["In","192.168.1.20",9]` | 40 | 20>40 |
| stat_object | 0/0 | `{"n":3,"total":1.5,"max":null}` | 32 | 0>8, 8>16, 16>32 |
| pair_vec | 0/0 | `[[["Out","10.0.255.7",8000],0.25],[["In","192.168.1.20",9],1e22]]` | 128 | 0>8, 8>16, 16>32, 32>64, 64>128 |
| quad_vec | 0/0 | `[[["Out","10.0.255.7",8000],12,18446744073709551615,-0.0]]` | 64 | 0>8, 8>16, 16>32, 32>64 |
| named_stat_iter | 0/0 | `[["a\"b\n",{"n":3,"total":1.5,"max":null}]]` | 64 | 0>8, 8>16, 16>32, 32>64 |

`controls.tsv` lists the mutants; `coverage.tsv` lists how many instructions of each function the cases executed.

## Implementation and comparison

`tools/transport_peer_json_115.py` contains (1) a copy of the shared offline interpreter (Image, decode, Memory, Machine), (2) the Python model (`Sink`, `Model`), (3) the rig that places a `Vec<u8>` of chosen capacity and prefix in memory, builds each argument (endpoint bytes, rows, B-tree nodes, iterator state, compound state), runs the real bytes and reads back status, capacity, bytes and growth events, and (4) the control batteries. The interpreter serves only: memcpy (slot 0x64df508), the allocator finish step 0x4787da0 (bump allocation, growth events are recorded), the ryu slot, and the two table slots.

- Cases: 14,430 (random inputs with digit-length, escape and float edge pools, plus sweeps in which every capacity from the prefix length to the output length is tried so each reserve site is the one that grows). Model mismatches: 0. Reserve events compared: 29,035.
- Negative controls: 126 in total, 125 detected, 1 equivalent (see `equivalent-mutants.tsv`). They are punctuation-byte and branch-inversion mutants of the code bytes, deliberately wrong models (escape ignored, upper-case hex, wrong reserve granularity, swapped direction, reversed octets, zero-padded octets, wrong null rule, swapped fields, missing brace, wrong row order) and out-of-range inputs (corrupted digest, mid-function entry, unmapped address, step limit, unmodelled allocator call).
- Closed domains are tried completely: all 256 byte values in a key (alone and between letters, both entry writers, both compound states), all 256 octet values in each of the four positions, decimal-length boundaries of 1 to 20 digits and fourteen port boundaries in both directions.
- `cases-sample.tsv` is every fourth case in generation order (input summary, initial and final capacity, growth events, truncated output hash); the generator is deterministic and rebuilds every case.

## Results and limitations

Results are in `measure.json`: `cases`, `negative_controls`, `negative_detected`, `equivalent` as above; the tests assert `negative_detected + equivalent == negative_controls`.

Limitations, stated plainly:
- The f64 text comes from a stub model of the ryu pretty formatter (the formatter at 0x5d0e4c0 uses SIMD instructions the interpreter does not decode). The bytes around it (when it is called, the null rule, reserve and copy) are verified; the digits and exponent rules of the stub are not.
- The B-tree path is driven for height 0 and height 1 trees with the front handle at the first leaf edge; deeper trees, partially consumed iterators and the lazy root state are not driven. The slice-pair state word 2 is described by behaviour only; which Rust type produces it is unresolved.
- One instruction (0x4776c32, a comma store on the zero-count path) is not reached by any well-formed iterator state and is recorded as an equivalent mutant with that argument.
- No gate is requested; this does not cover the transport framing, LZ4 or reconnect scope.

Next question: the callers of 0x4776230, 0x47775c0 and 0x4776de0 - which report type each writer serializes and where the Vec buffer is handed to the socket or the file writer.
