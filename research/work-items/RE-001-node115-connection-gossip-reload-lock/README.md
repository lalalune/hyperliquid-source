# RE-001: resolve connection-side synchronization around gossip metadata reload

RE-001 · Node runtime and gossip. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The connection caller synchronizes the gossip metadata reload through the qword at the shared object's offset `0x18`. If its byte at `+0x10` is nonzero, the caller skips the reload sequence. Otherwise it tries an atomic compare-exchange from 0 to 8, enters the reload block on success, and on failure calls a timed slow path before joining the same block. The reload receives the object region at `+0x20`.

The normal return path attempts an atomic 8-to-0 release. If that fails, the caller invokes the other slow path with a zero second argument and rejoins after the release. The two slow-path slots are separately relocation-backed. The [gossip reload packet](../RE-014-gossip-reload-115/README.md) establishes the behavior of the inner reload routine; this packet establishes the caller's synchronization and bypass conditions.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a628d0 --stop-address=0x5a63036 "$target"
readelf -rW "$target" | grep -Ei "64e0ff0|64e1000"
```

Verified the digest, caller/reload FDEs, both slow-path target FDEs and the lock prefixes. Recomputed both indirect slots and checked that the failed acquisition rejoins before reload, whereas the failed release rejoins after it. Exchanging those destinations contradicts the recorded jump operands.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The fast-path protocol and joins are established. The full slow-path implementation, timeout disposition, and runtime writer of the bypass byte remain open. This packet requests no acceptance gate or byte-coverage change.
