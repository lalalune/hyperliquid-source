# RE-001: resolve the RPC diagnostic format stream callback order

RE-001 · RPC diagnostics. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The #115 format interpreter dispatches two RPC location arguments in the order path, literal colon, line. At `0x1680594`, tag `c0` selects an implicit argument index. The interpreter shifts the index left by four and fetches the value pointer and function pointer from the resulting 16-byte entry. It advances the index after a successful callback.

[#3971](https://github.com/lalalune/hyperliquid-source/pull/3971) identified the callback bindings and the stream bytes. The [literal-stream packet](../RE-012-snapshot-format-literal-stream-115/README.md) established short literal consumption. Together with the newly traced `c0` arm, the bytes at `0x434571` decode as callback 0, length-one literal `3a`, callback 1, terminator. A nonzero callback status exits before advancing the index.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1680500 --stop-address=0x16806b1 "$target"
objdump -s -j .rodata --start-address=0x434571 --stop-address=0x434576 "$target"
```

Verified the target SHA-256 and FDE, decoded the tag comparison and callback-table operands, and replayed the five-byte stream using the observed transitions. Substituting zero for the literal-length byte ends the stream before the second callback in the model.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The decoded sequence describes the all-success path. Remaining directive encodings and the formatting sink's runtime behavior are outside this packet. This packet requests no acceptance gate or byte-coverage change.
