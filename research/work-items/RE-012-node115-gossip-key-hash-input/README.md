# RE-012: selected node 115 request-key hash inputs

[PR #5080](https://github.com/lalalune/hyperliquid-source/pull/5080) traces a zero-tag key to `0x4ef8bb0` and leaves its hash boundary unresolved. This packet maps the bytes supplied by `0x4e527a0` to the shared update helper. It uses Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The existing `RE-001-listener-hash-tail-update-115` independently studies `0x4ecead0`; its update algorithm is a boundary here, not newly claimed.

## Selected input construction

`0x4ef8bb0` calls `0x4e527a0` at `0x4ef8bc8`, retaining its key pointer for later comparisons. In the hash helper, the key's byte at `+0` is zero-extended to a qword and copied to a stack buffer. The first call to `0x4ecead0` receives that buffer and length 8. A second call receives bytes beginning at key `+1`, with length 16 if the raw tag byte equals 1, and length 4 for every other raw byte value. The calls are ordered as written and use the same local state. For the zero tag staged on the selected request path in #5080, the selected input portions are therefore eight zero bytes followed by the four stored dword bytes, subject to normal helper returns and no interfering aliases. This is a call-input observation; the final hash value and complete algorithm are not claimed.

## Comparison branch and raw-tag boundary

After the hash call, the selected table helper tests bit 0 of the full tag byte. On the even arm it reads and compares one dword at `+1`; on the odd arm it reads and compares two qwords spanning `+1..+16`. Both selected candidate paths also compare the full tag byte. Thus raw tags 0 and 1 select matching payload widths at the hash and candidate-comparison boundaries: 4 and 16 respectively. For other odd raw bytes such as 3, the hash helper selects 4 while the comparator selects 16. This describes the local branch predicates only. It does not show that any such tag is valid, produced by a decoder, or reachable from a live request, and it does not establish a collision, lookup result or vulnerability.

Table probing, hasher state initialization, the update helper's internal operation, all helper side effects, malformed storage and dynamic execution remain outside this packet. Pointers and buffers must be valid and non-aliasing along the selected route.

## Reproduce

From the repository root, run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-key-hash-input/verify.py`. The verifier authenticates the target and two FDE bodies, selected instructions and direct targets, and raw-tag boundary examples. It reads and decodes bytes only; it never executes or emulates the captured node.
