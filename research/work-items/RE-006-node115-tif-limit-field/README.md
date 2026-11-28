# RE-006 — Named Tif field in node #115 limit-order serialization

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The [Tif codec packet](../RE-006-tif-codec-115/) identifies three leaf serializers. This packet connects each leaf to one enclosing named-field path. In those paths, byte +9 of the order-type input equal to 2 selects an outer one-entry map with the fixstr key `limit`. The nested one-entry map writes the fixstr key `tif` when the serializer byte at +0x1b equals 1, then calls the corresponding leaf for the name. The leaf result is compared to `0x8000000000000004` before normal continuation.

| Enclosing entry | Call site | Enum serializer |
| --- | --- | --- |
| `0x25dad80` | `0x25dae5d` | `0x25da5c0` |
| `0x44983a0` | `0x449847d` | `0x4497590` |
| `0x520c170` | `0x520c29a` | `0x5192420` |

The third caller can also write the containing one-character key `t` before entering this branch. This establishes the named wire shape `{"limit":{"tif":"Alo"}}` for the leaf's tag 0 in the selected branch. Caller source identities, other arms and buffer growth are outside scope.

From the repository root run `PYTHONPATH=tools python3 research/work-items/RE-006-node115-tif-limit-field/verify.py`. It reads the binary to verify FDE extents, instruction windows, relative calls and the literal stores.
