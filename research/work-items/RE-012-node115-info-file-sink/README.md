# RE-012: trace the selected node #115 info callback to its file-descriptor sink

- Component ID: node-runtime (RE-012, APIs/gossip/startup)
- Target release and full SHA-256: Linux x86-64 node #115,
  `artifacts/node/115/hl-node`, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Claim status: **static observation** of the selected callback/context setup,
  buffered flush and terminal syscall argument path. Runtime success, the
  actual pathname and source ownership are not claimed.
- Scope: answer the next question from #5599 by following its selected
  `0x636c530` callback through the caller-initialized context to the terminal
  writer used for this output record.
- Excluded: resolving the runtime contents/provenance of the `.bss` pathname,
  proving a real file was created or written, other callers of these helpers,
  CLI reachability and reconstruction.

## Reproduce

Static-only commands; no captured executable is run.

```sh
make verify
make reproduce
python3 tools/fde_extents.py --release 115 --output-dir work/info-file-sink-verification
xcrun llvm-objdump -d --start-address=0x63d4c44 --stop-address=0x63d4cd0 artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x63d5333 --stop-address=0x63d53e0 artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x636c4a0 --stop-address=0x636c52c artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x636c530 --stop-address=0x636c612 artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x636c620 --stop-address=0x636c672 artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x63d3b90 --stop-address=0x63d3bd3 artifacts/node/115/hl-node
python3 -B research/work-items/RE-012-node115-info-file-sink/verify.py
```

Recorded environment: macOS arm64, Python 3.14.3 and Apple LLVM
`llvm-objdump` 21.0.0. The exact target signature, target/import manifests and
inventories were verified. In this sparse checkout, `make verify` checked the
three packet manifests present; this is not a full-repository manifest census.
`make reproduce` regenerated both retained inventories. `make doctor` reports
that GNU `objdump` and `readelf` are missing; Apple LLVM was used for these
exhibits. No captured binary or target filesystem write was executed.

`verify.py` checks the full target digest, six raw code windows and their FDE
extents. It also confirms the checked-in disassembly windows are bound to
exact code bytes; changing a byte in a synthetic exhibit fails that comparison.

## Evidence

The owner FDE is `0x63d4bbe..0x63d5428` (2,154 bytes; FDE record
`0x103a7cc`). Relevant callee extents are:

| Role | FDE range | Bytes | FDE record |
| --- | --- | ---: | --- |
| callback/context initializer | `0x636c4a0..0x636c52c` | 140 | `0x102f04c` |
| selected buffered callback | `0x636c530..0x636c612` | 226 | `0x102f078` |
| buffered flush and cleanup | `0x636c620..0x636c672` | 82 | `0x102f0c4` |
| terminal writer | `0x63d3b90..0x63d3bd3` | 67 | `0x103a3fc` |

These are `.eh_frame` extents, not source-level function-boundary proof.

In the selected owner, when `.bss` byte `0x67157f0` is zero, the code passes the
pointer stored at `.bss` address `0x67147e0` and mode `0x1a4` (0644) to
`creat@plt`. The returned descriptor is kept at `rsp+0x48`. If the guard byte
is nonzero, this branch skips `creat` and stores descriptor value zero; the
selected terminal writer also checks that same guard and returns without a
syscall in that case. A failed `creat` follows a separate error path and is
outside the successful-write path described here.

The owner then initializes a context at `rsp+0xc0` through `0x636c4a0`, passing
callback `0x63d3b90`, context pointer `rsp+0x48`, null initial buffer, and size
65,536. The initializer stores the callback at context offset `0`, the
descriptor pointer at `+8`, and requests a 65,536-byte allocation. It stores
the allocator result at `+16`, logical capacity 65,535 at `+24`, length zero
at `+32`, and sets an owned-buffer flag at `+40`. Allocation failure leaves
the buffer pointer null; the sink then does not establish a write.

The info formatting bridge selects `0x636c530` with the initialized context as
its argument. That sink appends each formatted chunk to the context buffer. On
capacity, it NUL-terminates the accumulated bytes and calls the context's
callback at offset `0` with the context pointer at `+8` and buffer pointer at
`+16`. The owner also calls `0x636c620` with the same context at its epilogue;
that helper NUL-terminates and flushes any remaining bytes before releasing
the owned buffer. This accounts for both full-buffer and final partial-buffer
paths.

The terminal callback at `0x63d3b90` checks `.bss` byte `0x67157f0`; when clear,
it measures the supplied NUL-terminated bytes with `strlen`, loads the file
descriptor through the saved context pointer, and calls `syscall@plt` with
number `1`, that descriptor, the buffer pointer and its length. Interpreting
Linux x86-64 syscall number 1 as `write` is an ABI-based inference from the
target and argument order. The return value is stored at context offset `+8`.
The owner later closes its descriptor.

Therefore the selected info record is routed to a descriptor created from the
runtime path pointer at `0x67147e0`, subject to the guards, successful
allocation and successful `creat`. The actual pathname bytes and whether any
write returned successfully remain unknown because `.bss` runtime values and
target execution are not observed.

Related evidence: #5599 establishes the preceding `info` literal → first `%s`
conversion → selected `0x636c530` callback chain. #2863 records the same owner
FDE's `creat` and callback setup arguments but leaves `0x63d3b90` opaque. #3732
concerns a separate snapshot file-path callback and does not cover this
buffer-to-descriptor route.

## Implementation and comparison

Not implemented or measured. No Rust reconstruction, source mapping, compiler
claim or comparison against rebuilt source exists. No acceptance gate is
requested or advanced.

## Results and limitations

- One selected callback chain was traced across five FDEs plus its owner FDE.
- The path from the formatter buffer to a descriptor is supported by direct
  call setup, context-field stores, callback loads and cleanup flush instructions.
- No pathname value, successful allocation, successful `creat`, syscall result,
  CLI role or source/dependency owner is inferred beyond the stated static facts.
- No captured binary was executed and no file was created by this analysis.
- All reconstruction gates remain false.

Next question: determine where the `.bss` pathname pointer `0x67147e0` is
initialized and what runtime modes select its guard, without running node #115.
