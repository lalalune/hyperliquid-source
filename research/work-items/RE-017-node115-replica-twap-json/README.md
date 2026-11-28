# RE-017 emit #115 TWAP order and cancellation results in replica Full JSON

The compact JSON result dispatcher sends `twapOrder` through `0x509e1f0` and `twapCancel` through `0x5098c90`. The two routes enter separate `data.status` writers at `0x51833f0` and `0x51837d0`. Each compares zero against the projected first qword and takes the ordinary error branch when signed overflow is clear. For the valid result descriptor, the reserved `0x8000000000000000` value selects success. A successful creation writes `{"running":{"twapId":ID}}` while a successful cancellation writes the string `"success"`. The structured error branch for either writes `{"error":"MESSAGE"}` inside the TWAP status. The outer action result still has status `ok` on these selected TWAP result arms. [Structured replica JSON dispatcher](../RE-017-node115-replica-success-dispatch/README.md) · [Separate MessagePack projection](../RE-001-node115-twap-result-projection/README.md) · [Existing typed Full emitter](https://github.com/lalalune/hyperliquid-source/pull/7530)

The authored Rust writer preserves both result levels and uses the existing entry escaper. The offline Full fixture includes successful creation with the complete unsigned maximum ID, successful cancellation, and both structured error statuses with escaped text. The outer typed emitter and existing tests run alongside it. This covers offline result serialization. TWAP creation, cancellation, scheduling, fills and state-root parity remain independent.

The verifier authenticates the Linux x86-64 node #115 capture SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, checks instruction spans in their unwind ranges and verifies compact branch targets, type descriptor relocations and literal references. The captured node is input data. Rust 1.95 builds the reconstructed writer integration in temporary storage using the exact #7530 source.

## Reproduce

From the repository root set `packet` to this directory and make the #7530 commit in `verify.py` available locally.

```sh
python3 -B -u "$packet/verify.py"
```

See the [raw verifier and Rust test output](offline-log.txt).
