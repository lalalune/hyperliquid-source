# RE-001: identify NV stream broadcast channel capacity normalization

RE-001 · Node runtime. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The callee at `0x5964590` constructs a broadcast channel. A zero input reaches the diagnostic `broadcast channel capacity cannot be zero`, and a set sign bit reaches the diagnostic for exceeding `usize::MAX / 2`. The accepted path rounds the capacity up to a power of two and initializes the shared object's offset `0x20` with the resulting capacity minus one.

The ordinary path uses BSR on capacity minus one to find the exponent. Capacity one bypasses that instruction. The constructor stores the same allocated pointer in its first two output slots after incrementing its leading atomic count. [#3969](https://github.com/lalalune/hyperliquid-source/pull/3969) recorded the call site without resolving the callee's role.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5964590 --stop-address=0x59646cc "$target"
objdump -s -j .rodata --start-address=0x93847a --stop-address=0x9384d7 "$target"
```

Verified the ELF digest and constructor FDE. Checked the two exact diagnostic spans, BSR operands and mask store. Replayed boundary capacities including one, a non-power-of-two value and a value rounding to the high bit. An identity-capacity model disagrees for input 17.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The arithmetic result precedes allocation. The packet does not claim large allocations succeed or recover send and receive behavior. This packet requests no acceptance gate or byte-coverage change.
