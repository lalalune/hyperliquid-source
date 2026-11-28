# RE-017 #115 local JSON Context hardfork projection

Component `abci`. The selected JSON local restore route has a distinct Context visitor from the [MessagePack route](../RE-017-node115-local-context-hardfork/README.md). On its selected successful map return, the JSON `hardfork.version` and `hardfork.round` occupy Context output +0x18 and +0x20. This pins the JSON pair used by fixtures before it enters the outer restore copies.

| Boundary | Evidence |
| --- | --- |
| Local JSON route | The file reader calls `0x1d74270`, which calls `0x1f3d760`. The selected child calls continue to `0x1f2bd40` and the Locus visitor `0x1f7e100`. |
| Locus map | The three-byte `ctx` comparison in `0x2a6d7a0` returns index zero. Its table arm's duplicate diagnostic names the same field. The regular value call at `0x1f7ee4f` reaches Context visitor `0x1f8e960`, with result at stack+0x338. |
| Context map | Index 1 names `hardfork` in its duplicate diagnostic. The normal field branch calls `0x1f32740`. The child matches the exact key fragments for `version` and `round`, calls the same scalar reader, and stages the values separately. The selected child success stores version at output+8 and round at +16. |
| Pair return and caller | The Context stages the ordered result at stack+0x110 and marks the field present. Its selected successful map join uses the presence bit to retain both words or select all zero bytes when omitted. It writes the pair as one span at `0x1f8ec97`. The Locus caller takes version from the high qword loaded at stack+0x348 and round from the low qword loaded at +0x358. Those words reach its stage at +0x2c8/+0x2d0, respectively. |

The claims apply to the selected normal object branches and successful scalar return. This packet stops at the Locus staging slots. It does not establish full JSON parsing, the remaining outer aggregate copies, a real local file's values or any state-root result.

## Offline verification

Run from the repository root:

```sh
python3 -B research/work-items/RE-017-node115-local-json-hardfork-pair/verify.py
```

The verifier authenticates the #115 artifact and checks table entries, diagnostic literals, call and jump targets, and the copy offsets inside FDEs. See [raw output](offline-log.txt) and [instruction windows](windows.txt).
