# evm: family-3 typed envelope and payload tail dispatch

Component: `evm`. This answers the distinct `0x5b69bb0` question left open
by `evm-tx-type-name-codec-115`: family 3 has a different envelope convention
from the two-field signed envelopes covered there. The four-field result
record `0x5b5e2e0` is a different body and is not owned by this packet.

Target: node #115 Linux x86-64, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
Actual FDE `0x5b69bb0..0x5b6a093`, 1,251 bytes / 309 instructions.
Complete bytes, FDE/CIE records, branch/call edges and dispatch table retained.

## Observed interface and branch sequence

Entry arguments: RDI output record; RSI buffer descriptor; RDX key address;
RCX key length; R8 enum object. The buffer descriptor has mode byte +0x1b,
capacity +0, storage +8 and length +0x10.

If mode is nonzero, the body first calls `0x57cf5d0` with the buffer, incoming
key pointer and incoming key length. RAX=2 permits enum dispatch. Any other
RAX returns output qword 0x8000000000000000 and stores that RAX and RDX at
output +8/+0x10. Mode zero skips this outer-key call entirely.

Dispatch loads the full qword discriminator from the enum, advances the
payload pointer by 0x10, and indexes table 0x93e278 using the qword as an
unchecked index. Signed i32 offsets are added to the table base. Only tags
0..4 are qualified; no masked-byte fallback is implied by this load.

| Tag | Table target | Emitted singleton-map prefix | Typed payload tail target |
| --- | --- | --- | --- |
| 0 | 0x5b69bf6 | `81 a6 Legacy` | 0x5b5ecf0 |
| 1 | 0x5b69dbc | `81 a7 Eip2930` | 0x5b5fd50 |
| 2 | 0x5b69ce6 | `81 a7 Eip1559` | 0x5b5f6d0 |
| 3 | 0x5b69d51 | `81 a7 Eip4844` | 0x5b60450 |
| 4 | 0x5b69c7b | `81 a7 Eip7702` | 0x5b60850 |

The prefix column uses hex marker bytes followed by literal ASCII name bytes.
Every arm emits 0x81 and its fixstr name independently of the buffer mode.
Thus disabling the outer key does not turn the variant itself into an array.
There is no two-field payload/signature envelope inside this body.

Each arm finishes with RSI=enum+0x10, RDX=buffer and the original output RDI,
then restores saved registers and tail-jumps to its typed payload writer.
The verifier requires each external direct tail to match its explicit site
and target and to start an actual FDE. Those payload bodies are boundary
context; their fields and behavior are not recovered here.

Three local storage needs per arm (one map marker, one string marker, then
the name bytes) have growth paths through `0x5963a10`, arguments alignment
1 and required length 1, 6 or 7. The code reloads descriptor fields and
rejoins the appropriate store. The allocator/grow helper remains opaque.

## Reproduce, controls and limits

```sh
python3 research/work-items/evm-family3-typed-envelope-115/verify.py
```

Python, Capstone 5.0.6 and pyelftools 0.32; `--write` regenerates exports.
The verifier authenticates the full image, actual FDE, complete decoding,
instruction pins, direct branches, five external tail destinations and the
five-row table with in-body instruction-boundary targets. Nine operative
mutations (including table data) must reject below the image SHA guard.

Independent conditional prefix checks cover 256 mode bytes, five outer-key
result representatives and all five valid tags: 6,400 cases. They distinguish
nonzero mode from exactly-one mode and verify the singleton map remains after
the outer-key gate. They do not execute or interpret captured instructions.

Assumptions: valid discriminator 0..4, valid source/storage pointers and buffer
metadata, stable nonaliasing objects and normally returning key/grow helpers.
Key encoding, typed payload encoding, allocation failures, concrete Rust types,
unwinding and full EVM acceptance remain open. No progress gates change.

Next question: recover each typed payload writer's source-field layout,
map/array cardinality and failure propagation without conflating this enum
object's +0x10 payload with the original enum base.
