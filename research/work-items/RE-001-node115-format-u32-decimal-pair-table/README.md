# RE-001: reconstruct the node #115 unsigned decimal digit staging algorithm

RE-001 · Foundation utilities. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The formatting callback at `0x15eb990` converts an unsigned 32-bit value into a decimal byte slice. It uses a 200-byte digit-pair table at `0x46ea12` containing ASCII `00` through `99`. The large-value loop peels four digits using multiply-and-shift division by 10,000, splits the remainder into two digit pairs, and stores them backward. The cleanup emits a final pair and a leading digit only when needed, including the special zero case.

[#3971](https://github.com/lalalune/hyperliquid-source/pull/3971) identified the callback as the consumer of the line field. This packet recovers the digit-staging behavior through `0x15eba6b`, where the pointer and length are passed in `r8` and `r9`. For each reciprocal multiplier, the maximum scaled error is smaller than the remainder gap required to round the quotient upward over the stated operand range.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x15eb990 --stop-address=0x15eba8a "$target"
objdump -s -j .rodata --start-address=0x46ea12 --stop-address=0x46eada "$target"
```

Verified the target SHA-256, exact FDE and 200 table bytes. Replayed the recovered arithmetic and table indexing for 10,006 inputs against decimal conversion, including zero, the loop transition and the maximum u32. Changing the table entry for 42 to XX changed that result in the model.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The comparison covers the staged decimal slice. It does not cover padding and output sink behavior after the indirect call. This packet requests no acceptance gate or byte-coverage change.
