# RE-001: resolve the Info API future completion and panic states

RE-001 · Info API. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The #115 Info API future at `0x2979780` uses byte offset `0x18` as a resume state. State zero runs the inner operation and, on normal return, writes state one before returning a result. State one routes to a handler that supplies the exact literal `async fn resumed after completion`. Other nonzero states route to the separate handler whose literal is `async fn resumed after panicking`. A cleanup fragment writes state two before forwarding the unwind payload.

[#3953](https://github.com/lalalune/hyperliquid-source/pull/3953) recorded the zero-state edge. This packet resolves the meaning of that byte through the two separate relocation-backed diagnostic bodies and records the stores that distinguish normal completion from cleanup.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2979780 --stop-address=0x29797f9 "$target"
objdump -d -M intel --start-address=0x1681e60 --stop-address=0x1681e99 "$target"
objdump -s -j .rodata --start-address=0x46f2ed --stop-address=0x46f332 "$target"
readelf -rW "$target" | grep -Ei "64e136[08]"
```

Verified the target digest and all three FDEs, resolved both indirect calls, and matched the separate message spans in .rodata. Swapping the two expected literals fails the byte comparison. The cleanup store is statically observed; the packet does not infer LSDA coverage from the FDE alone.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The inner operation's request-level behavior and the precise unwind-table edge remain unresolved. This packet requests no acceptance gate or byte-coverage change.
