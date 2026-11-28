# RE-009 Node #115 positional MessagePack checkpoint root cadence

The positional MessagePack checkpoint reader takes the last value of the historical 12-field `ExchangeMisc` array as the replay root cadence. A missing final value defaults to 1,000 on this arm, as does an explicit zero. A nonzero value is preserved as a full 64-bit word. This extends the [keyed restore path](../RE-009-node115-checkpoint-root-cadence/README.md) and the [export path](../RE-009-node115-checkpoint-cadence-export/README.md) to the reader for compact positional data.

- Component: `storage` / `abci`.
- Input: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base revision: `cfeaee133b33ce9450a7434af19515b82171a8c6`.
- Coordinates and method: ELF virtual addresses, decoded with LLVM objdump 23.1.4 using Intel syntax. The verifier checks the original instruction bytes and FDE ranges directly against the digest-pinned ELF.

## Evidence

| Step | Selected addresses and result |
| --- | --- |
| Container | The Exchange handoff at `0x2fd8164` still calls `0x31050e0`. The nested fixed-array marker arm masks the low nibble at `0x310515a` and passes the resulting count to the array body `0x31052b0`. The writer's corresponding unnamed arm at `0x3d2f112` passes count 12 to `0x3d50270`. It reaches the final field call at `0x3d2f48b` with subrecord word `+0xc0`, then returns the writer status. |
| Field | `0x31074ae` calls `0x3041e40` with the sequence state at stack `+0xc0` and output at `+0x60`. The helper reads the remaining count at sequence-state `+8`. At zero it returns tag 9 and a zero word without reading another item. Otherwise it decrements the count and calls through `0x64e2588`. The successful result carries the selected value at result `+8`. |
| Default | At `0x31074b9..0x31074d0` the parent checks tag 9, tests the full returned word and selects 1,000 when the word is zero. Both explicit zero and an exhausted sequence use this selection. The non-success tag takes a separate return path before selection. |
| Restore | The selected word is stored at stack `+0x398` at `0x3107669`. On the normal result path the `0xf8`-byte copy from stack `+0x2d8` keeps it at subrecord `+0xc0`, and the second `0xf8`-byte copy publishes the subrecord. The existing parent/materializer witness then carries that same slot to historical state `+0x1ea8` and live state `+0x39c8`. |

The field name `aci` follows from the previously recovered keyed writer and keyed visitor using the same subrecord coordinate. The observed default applies to this final field when the earlier fields and enclosing checkpoint have already been admitted. It does not establish acceptance of every shorter array. The offline verifier checks the positive branch and uses a nearby wrong-default opcode and wrong qword coordinate as negative evidence controls. No captured code executes and no private or live checkpoint is required. The complete checkpoint data model, real state root and replay result root remain separate acceptance work.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-positional-msgpack-root-cadence/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
