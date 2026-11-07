# RE-001: recover the NV stream paired reference cleanup

RE-001 · Node runtime. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The NV stream loop clears its stored element count before visiting a collection of 16-byte pointer pairs. For each pair it atomically decrements the first pointed-to qword, conditionally calls its cleanup routine on a zero result, then does the same for the second pointer using a different routine. Each routine receives the address of the corresponding pointer slot. The resolved callback FDE starts are `0x5a8d7c0` and `0x5a8b3e0`.

[#3969](https://github.com/lalalune/hyperliquid-source/pull/3969) recorded a branch in this caller. The new evidence establishes the collection layout, cleanup order and zero-transition condition.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a860f2 --stop-address=0x5a8614d "$target"
readelf -rW "$target" | grep -Ei "64e4f(98|a0)"
```

Checked the artifact digest, enclosing FDE, two lock prefixes and both relocation-backed callback FDEs. Starting from counter one, the decoded decrement reaches zero and invokes cleanup; starting from two it skips cleanup.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

Reference ownership is inferred from the atomic decrement pattern. The concrete pointee types and callback implementations remain open. This packet requests no acceptance gate or byte-coverage change.
