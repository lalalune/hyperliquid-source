# RE-001: recover the NV stream 80-byte to five-byte record projection

RE-001 · Node runtime. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The NV stream scalar tail compacts five bytes from each 80-byte record. It loads a dword at offset `0x45` and a byte at offset `0x49`, writes them contiguously and advances source and destination by 80 and five bytes.

The next block requests 48 bytes through a relocation-backed call to `0x6355830`. On non-null return it initializes two leading qwords to one and populates four more qwords before passing the object onward. [#3958](https://github.com/lalalune/hyperliquid-source/pull/3958) recorded the branch. This packet identifies the input projection and what produces the value tested at that branch.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2af45f0 --stop-address=0x2af560e "$target"
readelf -rW "$target" | grep -i 64df480
```

Verified the digest, copy instructions, two FDEs and the allocation slot. Applied the observed offsets and strides to two synthetic records. Increasing the source offset by one changed both projected groups.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The application meaning of the projected fields and precise object type remain open. This packet requests no acceptance gate or byte-coverage change.
