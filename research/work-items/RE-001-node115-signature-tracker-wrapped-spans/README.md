# RE-001: recover wrapped 80-byte spans in the signature tracker iterator

RE-001 · Block execution and state. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The signature-tracker caller builds a tag-2 descriptor holding two half-open ranges over 80-byte records. The builder conditionally subtracts the capacity-like bound once from the start index. It compares the requested length with the remaining capacity and splits a wrapping span into a tail and a prefix. For zero count it supplies empty ranges.

The builder scales indexes by 80, adds the backing base, and places the four pointers immediately after the tag. The callee at `0x4e40990` loads those fields and dispatches on tag two. [#3963](https://github.com/lalalune/hyperliquid-source/pull/3963) recorded the call edge. This packet recovers the data passed to the iterator and its wrapping rule.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x537b071 --stop-address=0x537b123 "$target"
objdump -d -M intel --start-address=0x4e40990 --stop-address=0x4e409da "$target"
```

Verified the digest, caller and callee FDEs, and the three scale operations. Replayed wrapped, nonwrapped, normalized-start and empty inputs. The wrapped fixture disagrees with a model that emits one contiguous range.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The replay assumes a valid capacity, start below twice capacity and count at most capacity. Full iterator behavior and record meaning remain unresolved. This packet requests no acceptance gate or byte-coverage change.
