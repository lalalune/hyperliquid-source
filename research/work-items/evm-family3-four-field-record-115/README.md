# evm: family-3 four-field result record

Component: `evm`. Answer the `0x5b5e2e0` question explicitly left open in
`evm-tx-type-name-codec-115`. That packet owns the other families' type names
and visitors. This packet owns the family-3 enclosing record's local wiring,
not the opaque integer/log writers or transaction encoding.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

## Binary-backed observations

New record body: actual FDE `0x5b5e2e0..0x5b5e934`, 1,620 bytes / 376
instructions. Marker helper `0x57d0b20..0x57d0b6e`, 78 bytes / 26 instructions,
is included as contract context (also referenced in order-status work), not
counted as a newly discovered function. Exports retain complete body and
FDE/CIE bytes, every call and branch, and the used constant/table bytes.

Entry RDI is the output record, RSI the source and RDX the buffer descriptor.
The descriptor has capacity +0, storage +8, length +0x10 and mode +0x1b.

| Order | Field | Source / local operation |
| --- | --- | --- |
| 1 | `tx_type` | source byte +0x21; unchecked five-row signed-relative table |
| 2 | `success` | source byte +0x20, OR 0xc2, marker helper, store AL |
| 3 | `cumulative_gas_used` | source qword +0x18 passed in RDX to `0x57cfd20` |
| 4 | `logs` | original source pointer passed in RDX to `0x5276290` |

At `0x5b5e2f7..0x5b5e318` the header is the low byte of
`((mode XOR 1)<<4) OR 0x84`: mode 0 emits array header 0x94; mode 1 emits
map header 0x84. The first key is emitted for any nonzero mode (`0x5b5e328`),
but the remaining three keys require mode exactly 1. Mode 2 therefore emits
0xb4 and only the first key; it is not ordinary map mode.

Both type dispatch sites (`0x5b5e382`, `0x5b5e392`) use table 0x93e1e8.
Its five signed i32 rows resolve to `0x5b5e394`, `0x5b5e4a1`, `0x5b5e429`,
`0x5b5e465`, `0x5b5e3ea`, respectively: fixstr names Legacy, Eip2930,
Eip1559, Eip4844, Eip7702. There is no bounds check here. Only input tags
0..4 are claimed; table-adjacent bytes do not define an enum fallback.

The success byte is ORed with 0xc2 at `0x5b5e53a`, then passed in EDI to
`0x57d0b20`. That helper immediately returns its first argument when its
low byte is in 0xc0..0xdf. Thus valid boolean bytes 0/1 emit c2/c3. Arbitrary
source bytes are not normalized to booleans; inputs outside this helper arm
can depend on ESI and remain outside the wire claim.

The 19-byte gas key combines the 16 bytes at 0x93edc3
(`cumulative_gas_u`) with an overlapping four-byte `used` store at offset 15.
The overlap writes the same `u`. The logs key is length 4 at 0x459e60 and
is written through `0x57cf5d0`, rather than inline stores.

## Result and call contracts

After the gas writer, stack qword 2 allows logs processing. Any other value
returns output discriminator 0x8000000000000000 and copies the two writer
result words to output +8/+0x10. In map mode the logs-key writer must return
RAX=2; otherwise its RAX/RDX pair is repackaged under the same discriminator.
The logs-value writer result discriminator 0x8000000000000004 writes that
value to output without copying payload. Other logs-value results copy all
three words. These are representation observations, not inferred Rust enum
definitions or a proof of semantic success/error names.

Buffer-full and insufficient-room paths call `0x5963a10` with required
growth lengths and alignment arguments 1, reload fields and rejoin the
corresponding stores. Allocation behavior remains opaque. The gas writer,
logs-key writer and logs-value writer are boundary contracts only.

## Reproduce and limits

```sh
python3 research/work-items/evm-family3-four-field-record-115/verify.py
```

Use Python, Capstone 5.0.6 and pyelftools 0.32. `--write` regenerates exports.
The verifier checks full target SHA, actual FDEs, complete decoding, instruction
pins and direct branch boundaries. Both indirect jumps are explicitly tied to
the pinned table, whose five targets must be instruction boundaries. Constants
are mapped through file-backed ELF sections. Ten operative mutations, including
a jump-table byte, must reject with the full-image SHA guard disabled.

Independent finite checks cover 256 mode bytes, five valid tags and two valid
boolean bytes: 2,560 prefix cases. This is a conditional scalar reconstruction,
not target execution or an instruction interpreter. Buffer invariants, valid
tags/booleans, stable nonaliasing objects and normally returning helpers are
assumptions. No allocator, integer/log payload, unwinding, whole-node or
component-gate claim. No progress gate changes.

Next question: recover the separately shaped family-3 envelope `0x5b69bb0`
and its five typed payload tail calls, keeping its input convention distinct
from the result record here.
