# RE-001: recover the transient timing publication around a lock acquisition

RE-001 · Runtime timing. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The caller publishes a nonzero nanosecond value at object offset `0x118` before acquiring the lock at `+0x6a8`. It passes a fresh monotonic timestamp and the stored pair at `+0x120/+0x128` to the known timespec-difference helper. For a zero difference tag it multiplies the seconds by one billion, adds nanos, saturates at u64 max, and replaces zero with one. A nonzero tag produces one.

The atomic exchange at `0x2a5cd33` publishes the value. Both successful fast acquisition and the relocation-backed slow path reach a second exchange at `0x2a5cd59` that clears it. A stored nanoseconds field of one billion bypasses this publication sequence and takes the alternate acquisition path. The [timespec-difference packet](../RE-012-timespec-difference-115/README.md) identifies the shared helper; this packet resolves this caller's publication and clearing protocol.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2a5cc50 --stop-address=0x2a5cfa8 "$target"
readelf -rW "$target" | grep -i 64e0ff0
```

Verified the target digest, caller and slow-path FDEs, relocation addend, both exchanges and branch destinations. Replayed zero, ordinary, nonzero-tag and overflow cases. A wrapping arithmetic control disagrees with the observed saturation path.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The packet establishes the writer's protocol. The readers of the published field and the source-level name of the containing object remain open. This packet requests no acceptance gate or byte-coverage change.
