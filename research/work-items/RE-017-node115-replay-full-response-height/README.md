# RE-017 · Node #115 Block output supplies Full replica responses and height

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `2da45cb0a761cff6b478e40421699857d87a94df`. The addresses below are linked ELF virtual addresses.

## Question

The [replay result cleanup](../RE-017-node115-replay-result-cleanup/README.md) packet traces the selected result staging and cleanup decision. The [result digest](../RE-017-abci-result-digest-115/README.md) packet maps the non-Full fingerprint branch and the earlier wrapper height source. The [replica response writer](../RE-017-node115-replica-response-source/README.md) packet establishes the JSON variants. This packet checks the join from replay output to the Full JSON writer and the adjacent height field for the same record.

## Selected normal route

| Stage | Evidence |
| --- | --- |
| Capture the Block wrapper output | On the selected wrapper path, expanded-state `+0x28` is read at `0x4fcb874` and staged at stack `+0x68`; the final copy at `0x4fcbbb3` emits it at wrapper output `+0x18`. The replay worker passes stack `+0x60` as the output buffer at `0x5a6ea10`. Immediately after the call, it saves the first three output qwords at `+0x180/+0x188/+0x190` and the separate `+0x18` word at stack `+0x120`. |
| Select the Full response | At `0x5a6f8c3..0x5a6f914`, callback byte `+0x6b8 == 1` selects the saved triple, restores it at worker stack `+0x67..+0x7e`, and clears `ecx`. The overlapping staging and record stores at `0x5a6f949..0x5a6f971` place tag byte 0 at record `+0x58` and the three words at `+0x60/+0x68/+0x70`. The last qword is also written separately at record `+0x78`. It lies outside the triple used by the Full row writer. |
| Deliver the corresponding height | `0x5a6ec5c` reloads stack `+0x120` before the branch that sets the periodic fingerprint value. The shared record constructor stages the height at `0x5a6ef02`, record `+0x80`. The worker sends stack `+0x120` in RSI and the record pointer in RDX to sink `0x595a6b0` at `0x5a6f991`. |
| Read the same triple and height in JSON | The selected initialized, no-roll sink route forwards the saved record pointer through `0x50e2f80` to serializer `0x4d6d740`. It passes record `+0x58` as `resps`; tag 0 passes the null and Hash tests and reaches the branch with the literal `Full`. That branch advances its input by eight and calls `0x502d0d0`. The writer's `+8/+0x10` loads select the two values at record `+0x68/+0x70`. After a successful response write, the separate `height` field receives record `+0x80` at `0x4d6d7de`. |

This selected path assumes an ordinary wrapper return with a valid response vector, callback byte one, an initialized no-roll sink and successful serializers. The cross-stage proof assumes that intervening helpers preserve the saved triple, height and record storage. In particular an earlier serializer wrapper also receives the staged record address at `0x5a6ef33`. The proof concerns operand provenance, with no captured or executed block, durability assertion, reference state-root equality, or inference about which real blocks select Full.

## Reproduction

```sh
python3 -B research/work-items/RE-017-node115-replay-full-response-height/verify.py
```

The [offline log](offline-log.txt) records the executed checks, and the [instruction spans](windows.txt) contain agreed GNU and LLVM encodings. The verifier authenticates the ELF, reconciles the selected FDEs against the unwind index, validates byte positions, decodes branch and call operands and checks the two serializer literals. A synthetic distinct-byte control checks the overlapping copies and keeps the row count separate from the adjacent height.
