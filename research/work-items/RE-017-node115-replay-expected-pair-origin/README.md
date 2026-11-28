# RE-017 #115 expected Block pair from the joined startup spawn

The selected Block gate in `nv_stream_forward_client_blocks` compares a decoded Block pair against two words in its future. The selected joined startup spawn supplies those words explicitly at input+0x100/+0x108, and the constructor preserves them at the same offsets in the allocated future. This traces the expected side of [the Block identity gate](https://github.com/lalalune/hyperliquid-source/pull/7247). The earlier [queue capture](../RE-017-node115-replay-queue-producer-capture/README.md) establishes the same task construction for the separate pointer at input+0xc8.

## Joined startup input

| Selected caller | Source bytes | Staging before the constructor |
| --- | --- | --- |
| `0x2af45f0` at `0x2af5b03` | `0x2af5797` reloads pointer L saved by `0x2af523a`. On the selected tag-2 path, L was the pointed-to state carried at `0x2ad7140` result+0x30, as traced in [the startup state packet](../RE-009-node115-startup-result-task-state/README.md). `0x2af579c` copies L+0x18/+0x20. | Stack+0x60 to stack+0x740. The constructor input begins at stack+0x640. |

The 16-byte loads and stores preserve word order. The caller slot resolves to `0x5a81ed0`. The constructor first copies 0x118 bytes from its input to scratch, then copies a 0x2d80-byte frame starting from that scratch base into the selected allocation. The spawn descriptor at `0x64b91a8` resolves its poll at +0x18 to `0x5a82670`. That poll compares the words from the decoded Block against future+0x100 and +0x108 in order at `0x5a874b9` and `0x5a874c6`.

The pair comes from a completed result pointer. The other spawn caller has its own control flow and requires a separate provenance check. The persisted values of the expected pair and comparison against a real replay fixture remain open.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-replay-expected-pair-origin/verify.py
```

The verifier hashes the pinned ELF, checks instruction bytes and their FDE bounds, resolves the constructor call and the poll relocation, and recomputes the caller-to-guard offsets. See [the recorded run](offline-log.txt) and [selected instructions](windows.txt).
