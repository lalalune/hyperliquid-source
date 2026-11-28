# RE-009 #115 MessagePack context clock string writer

The named MessagePack context serializer writes `time` and `prev_time` from state `+0x60` and `+0x6c` as strings. The selected writer formats the date, appends ASCII `T`, formats the time of day, and sends the complete span to the MessagePack string writer. This establishes the value encoding on the [linked-commit serialization path](../RE-017-abci-linked-commit-115/README.md#serialization-observations-and-conditional-models), whose earlier packet stopped at the shared helper `0x4e0da40`.

- The two named calls at `0x4d93250` and `0x4d93278` supply the literal address and length in RDX and ECX and the respective state pointer in R8. Inside `0x4e0da40`, serializer configuration byte `+0xb` controls emission of the key through `0x57cf860`. The selected named path advances to the value helper `0x5307510` when the key writer returns RAX=2.
- In `0x5307510`, the selected value pointer reaches the date formatter through relative slot `0x64e1158` → `0x1628bc0`. The call at `0x5307586` takes `0x54` through the String writer's vtable entry `+0x20`, which resolves to `0x526e1a0` and writes the ASCII byte at `0x526e1f1` on the selected one-byte path. The input pointer advances by four bytes before the time formatter through slot `0x64e1160` → `0x162a760`. These formatter bindings also appear in the [hourly-line framing analysis](../RE-008-hourly-line-framing-115/README.md), where the caller and serialization sink differ.
- The formatted buffer pointer and length go to `0x57cf860` at `0x53075b8`. For lengths below 32 the writer selects the `0xa0` tag family and passes the length to `0x57d0b20`; that helper produces `0xa0 | (len & 0x1f)`. The selected no-growth arm writes this header before copying the formatted bytes.

The offline log includes a synthetic short-string example for the framing rule. The example supplies the formatter output explicitly. It does not execute the formatter, establish all date and fractional-second spellings, or prove which serializer emitted any particular real checkpoint. No root parity or progress gate is claimed.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-context-clock-string-writer/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
