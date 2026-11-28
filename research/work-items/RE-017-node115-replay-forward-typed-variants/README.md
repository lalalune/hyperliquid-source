# RE-017: Nonopaque variant routing in the #115 origin-prefixed writer

The [opaque forwarding packet](https://github.com/lalalune/hyperliquid-source/pull/7289)
maps tag zero from the external forward worker. The same writer at
`0x581f160` also serializes six different bodies. An offline format
description needs their dispatch so it does not treat a typed consensus
message as an opaque length-prefixed replay payload.

On the selected capacity-success path, the writer emits 20 origin bytes.
It tests the leading body word. A nonnegative word selects index 2. A
negative recognized discriminant selects the index obtained by XOR with
`0x8000000000000000`. Indexed signed displacements from `0x935b40` choose
the local blocks. The verifier checks entries zero through six without
making claims about out-of-domain in-memory values.

| Table index and emitted raw byte | Ordered body writers |
| --- | --- |
| 1 | Compact u64 `0x5822910`, QC writer `0x5966a30`, child `0x51ffde0` |
| 2 | Signature `0x59681d0`, Block header-with-parent writer `0x5967060` |
| 3 | Signature `0x59681d0`, child `0x5966b90` |
| 4 | Signature `0x59681d0`, timeout vote writer `0x59676c0` |
| 5 | Signature `0x59681d0`, child `0x5b561e0` |
| 6 | Signature `0x59681d0`, child `0x5b5b360` |

Writer identities reuse the [consensus byte matches](../RE-008-node115-consensus-bincode-encode-byte-matches/README.md).
The remaining labels are left as addresses. This establishes raw tags and
selected child order, without modeling each child, an original enum name,
transport, verification or runtime acceptance. All analysis reads Linux
x86-64 node #115 as data.

```sh
python3 -B research/work-items/RE-017-node115-replay-forward-typed-variants/verify.py
```

[Raw offline output](offline-log.txt) · [Instruction windows](windows.txt)
