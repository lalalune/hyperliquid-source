# RE-005: node 115 selected gossip error wire pairs

This packet connects the remaining tag-1/5/6 payload calls left open by [#5096](https://github.com/lalalune/hyperliquid-source/pull/5096) to the separately established `RE-005-varint-buffer-writer-115` u64 writer. The earlier decoder in [#2790](https://github.com/lalalune/hyperliquid-source/pull/2790) already established the tag arities and ordered u64 pair on the read side, and [#4228](https://github.com/lalalune/hyperliquid-source/pull/4228) established the enclosing response routes. This packet adds the selected handler-field provenance and connects those concrete fields to the write/count side; it does not claim the generic writer or decoder grammar as new. Target: Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Selected raw field provenance

Let A and B be the two request qwords, F the selected first-cache scalar and L the selected last-cache key from #5083. On the selected normal handler paths, the raw error output stores tag at `+0x10` and two qwords at `+0x18` and `+0x20`:

| Tag | Branch condition | First qword | Second qword |
| --- | --- | --- | --- |
| 1 | unsigned B-A borrows | A | B |
| 5 | A <= F | A | F |
| 6 | A > F and B > L | B | L |

The relation assumes the selected earlier branches, valid stable inputs and the normal lock-release route. It describes raw values, not established units or all ways to construct a tag.

## Selected count and write composition

For top qword 3 and low marker dword 1, #5096 establishes the three-byte prefix `00 01 TT`. For TT 1, 5 or 6, both selected table paths then pass input `+0x18` followed by `+0x20` to two u64 helper calls: the count path calls `0x5822b90`, and the write path calls `0x5822910`. The latter's generic 1/3/5/9-byte encoding and growth order are credited to `RE-005-varint-buffer-writer-115`.

For an unsigned value x define E(x) as: one byte x when x < 251; `fb` plus LE16(x) for 251 <= x < 65536; `fc` plus LE32(x) for 65536 <= x < 2^32; and `fd` plus LE64(x) otherwise. On the selected successful calls, with valid capacity and no overflow or interfering mutation, the appended bytes are `00 01 TT || E(first) || E(second)`, in that order. Starting from the zero count in #5094, the selected count is `3 + len(E(first)) + len(E(second))`, between 5 and 21 inclusive. The intermediate primitive may grow a buffer on other paths; this statement assumes the selected successful result and does not describe failed writes.

The result does not establish live reachability, framing, complete response serialization, field units, all tag producers, helper failure effects, actual sends or a node implementation. The selected local arithmetic and byte order are conditional on the cited static helper contract and valid stable storage.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-005-node115-gossip-error-wire-pairs/verify.py`. It authenticates the target, five FDE bodies, selected instruction bytes and branches and static width/boundary examples. It never executes or emulates the captured target.
