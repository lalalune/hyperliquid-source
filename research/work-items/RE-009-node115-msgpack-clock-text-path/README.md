# RE-009 #115 MessagePack checkpoint clock text path

The [Context value packet](../RE-008-context-values-115/README.md) binds `time` and `prev_time` to the `Time` newtype reader at `0x2f6fa30`. Its string branches consume MessagePack framing before passing the text to a separate adapter. That adapter uses the same format items and time constructor as the [JSON route](../RE-009-node115-json-time-format-items/README.md).

| Marker | Length source on the selected path |
| --- | --- |
| `a0..bf` | Low five bits at `0x2f6fb52`. |
| `d9` | One-byte count at `0x2f6fe61`. |
| `da` | Two-byte big-endian count, normalized at `0x2f6ff48`. |
| `db` | Four-byte big-endian count, normalized at `0x2f6ff67`. |

The selected branches meet at `0x2f6ff71`. With enough payload bytes, the cursor advances by the declared length and the selected span goes through the UTF-8 slot `0x64dfca8`. The ordinary UTF-8 success branch calls `0x472e750` at `0x2f6ffc8`. That adapter passes the same `0x6405668..0x6405818` format-item range to `0x1620be0` and calls the same `0x1627e60` constructor as the JSON adapter. It requires no unconsumed text, then returns the 12-byte value at `+4..+0xf` with MessagePack success tag 9.

Matching the two adapters at this boundary supports using the same calendar clock text in selected JSON and MessagePack fixtures. This does not establish whole-file acceptance, real checkpoint values or replay root equality.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-msgpack-clock-text-path/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
