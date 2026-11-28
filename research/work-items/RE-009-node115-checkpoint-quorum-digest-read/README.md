# RE-009 checkpoint quorum digest lookup for node #115

The selected MessagePack checkpoint contains historical quorum rows. To compare an explicitly chosen height against offline replay, this packet binds the row's digest bytes to their serialized field and extracts a candidate from a local named checkpoint. The target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source baseline is `6d9382f821930b10d181cb90fe4a32756fd8e069`. Addresses below are ELF virtual addresses.

[Outer binary state reader](../RE-009-abci-state-read-115/README.md) and [tracker checkpoint reader](../RE-017-node115-replay-delay-checkpoint-read/README.md) locate `exchange.advt`. The [tracker writer work](https://github.com/lalalune/hyperliquid-source/pull/4338) identified `qrs` but stubbed its helper. The [digest encoder census](../RE-008-hex-digest-callers-115/README.md) establishes the common lowercase hex formatter. This packet follows the callees that connect the quorum row to that formatter.

| Selected path | Evidence |
| --- | --- |
| Tracker to row writer | The named branch loads `qrs` from `0x7c8664`. Writer `0x4214250` passes tracker `+0x48` to `0x41903c0`. The latter emits an array and uses row writer `0x41c7230` with stride 104. |
| Row framing | The row writer emits two elements. Either the array helper receives count two or the other arm directly writes `0x92`. Both load the first word from row `+0x0` for the height and pass the body address at row `+0x8` to a separate serializer. |
| Digest framing | The body writers `0x4213b10` and `0x42136d0` emit either a three-field map or a three-element array. The former reads the literal `h` from `0x7c8682` and the latter writes the fixstr bytes `a1 68` directly in named mode. Both emit the digest first. |
| Digest bytes | Both body writers pass body `+0x40` (row `+0x48`), length 32, capacity 66 and a zero trim flag to relocated encoder `0x2eabb50`. Both MessagePack string writers use str8 for the resulting 66-byte `0x`-prefixed lowercase hex string. |

The attached windows were selected from LLVM 23.1.4 Intel-syntax output. Regenerate a span with `llvm-objdump -d --x86-asm-syntax=intel --start-address=START --stop-address=END artifacts/node/115/hl-node`. The selected starts and exclusive ends are `0x4214250..0x4214480`, `0x41903c0..0x4190800`, `0x41c7230..0x41c7754`, `0x4213b10..0x4213dd4`, `0x42136d0..0x4213b10`, `0x41c6110..0x41c6260`, and `0x41c6610..0x41c6824`.

Use the files in this packet from the repository root. The static check reads the pinned ELF as data. The lookup requires Python 3.11+ and the independently installed `msgpack` Python module, tested at 1.1.2. It reads an already decompressed named MessagePack checkpoint.

```sh
packet=research/work-items/RE-009-node115-checkpoint-quorum-digest-read
python3 -B "$packet/verify.py"
python3 -B -m unittest discover -v -s "$packet" -p test_extract.py
python3 -B "$packet/extract_qrs.py" /path/to/checkpoint.rmp --sha256 "$trusted_sha256" --height "$height"
```

The verifier tests the selected instruction bytes in their FDE boundaries and rejects a mutated key and digest length. The extraction tests cover exact-height selection, agreeing repeat rows, conflicting rows, unexpected digest shape, duplicate keys, invalid checksum, truncation and extra data. The tests use synthetic MessagePack. The lookup requires a SHA-256 of the **decompressed** bytes from an independent source, retains the exact row height, and emits a candidate for comparison. The other two payload members remain opaque. A historical row can hold quorum material without establishing which height it should be compared to in a particular replay run. The checkpoint source and quorum authority, correspondence with a replay reference root, and comparison at H and H+1 all require separate evidence. No real checkpoint with that evidence was used here.
