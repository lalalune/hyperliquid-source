# RE-009 #115 checkpoint root cadence export

Both selected historical checkpoint exporters emit the cadence qword at state `+0x1ea8` as `exchange.msc.aci`. The [MessagePack restore packet](../RE-009-node115-checkpoint-root-cadence/README.md) and [JSON restore packet](../RE-009-node115-json-root-cadence/README.md) follow the other direction, from the nested reader to the periodic root divisor.

| Format | Field wrapper and value source | Selected numeric sink |
| --- | --- | --- |
| MessagePack | `0x3c15459` passes the historical subrecord at `+0x1de8` to `0x3d2f090`. In the named configuration it writes `msc` and opens the nested 12-field map. At `0x3d2f47c` it loads the qword at subrecord `+0xc0` and hands it to the keyed `aci` writer `0x3d33060`. | Unsigned MessagePack writer `0x3d517e0`. The wrapper passes the word on its positional arm as well, without the field name there. |
| JSON | `0x3c2fd8c` passes subrecord `+0x1de8` to `0x3d2c480`, which writes the key `msc` and opens the child object through `0x3c2df50`. The child passes pointer `+0xc0` with key `aci` to `0x4647ff0`. | Full qword load at `0x464800c`, followed by unsigned decimal conversion through `0x46ef580`. |

The offline log shows a synthetic cadence value of 1,000 as `cd 03 e8` in MessagePack and `1000` in JSON. The MessagePack width rules are established by the [unsigned writer packet](../RE-015-rmp-write-uint-b-115/README.md). This packet binds the new field path rather than re-deriving that writer. The examples describe the value payload only and do not imply a complete captured checkpoint or a matched replay root.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-checkpoint-cadence-export/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
