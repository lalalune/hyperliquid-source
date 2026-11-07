# RE-001: recover the TLS-derived callback drain order and sentinel

RE-001 · Foundation utilities. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The callee behind the foundation diagnostic path drains a callback array obtained from thread-local state. The loop reads the count at object offset `0x38`, checks for zero, then decrements and stores it before accessing the entry. Each 16-byte entry supplies a pointer to a callback table and a context pointer. The routine invokes table offset `+8` with the context in `rdi`, which establishes reverse array order for an unchanged array.

The object field at offset `0x20` must be zero before entry. The loop writes all ones before calling a callback, increments the field after return, and continues only if that increment yields zero. Thus a callback that leaves the sentinel untouched returns the field to zero. [#3952](https://github.com/lalalune/hyperliquid-source/pull/3952) recorded how the caller reaches this routine; it did not recover the drain protocol.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x24519c0 --stop-address=0x2451a7f "$target"
```

Verified the target SHA-256 and function FDE and checked the count, stride, argument and sentinel operands. Replayed the stable-array index arithmetic for zero, one and three entries. A forward-order expectation disagrees for three entries.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The model assumes callbacks leave the array and guard field unchanged. The table slot's source-level type and the TLS object's full lifecycle remain unresolved. This packet requests no acceptance gate or byte-coverage change.
