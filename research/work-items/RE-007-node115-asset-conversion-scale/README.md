# RE-007: #115 asset-registration conversion scale

The [asset-registration path packet](../RE-007-node115-asset-registration-path/README.md) identifies a call with a 16-byte payload, mode 2 and scale byte `6 - A`, but leaves the converter `0x421e9d0` open. This packet establishes the selected scale factors and a bound on a successful returned qword. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses. All observations are static; target instructions are not executed or emulated.

## Caller and scale

On the prior packet's selected bounded-index path, `0x3c42660` reads byte `A` from the selected 0x20-byte row at `+0x1d`. The unsigned check at `0x3c426c0` rejects `A >= 7`. Otherwise the caller computes `6 - A`, passes it in `ecx`, sets `edx = 2`, and calls through `0x64e6468`. Its relative relocation addend is `0x421e9d0`. Therefore the only scale bytes on this selected call edge are 0 through 6; this is not a claim about the converter's other callers.

The converter begins with factor 1. Its selected scale instructions use bits 0, 1 and 2 to multiply by 10, 100 and 10,000 respectively. On these seven values the factor is exactly `10^(6 - A)`, without 64-bit overflow:

| A | Scale byte | Factor |
|---:|---:|---:|
| 0 | 6 | 1,000,000 |
| 1 | 5 | 100,000 |
| 2 | 4 | 10,000 |
| 3 | 3 | 1,000 |
| 4 | 2 | 100 |
| 5 | 1 | 10 |
| 6 | 0 | 1 |

The converter passes that factor alongside a copy of the payload to the function reached through slot `0x64ea6a0`. A nonzero result dword selects output word `0xac`. If it is zero, the selected caller's mode byte 2 takes the path through slot `0x64ea6b0`; a later call uses `0x64ea6a8`. These helpers' arithmetic and rounding semantics are not reconstructed, so the factor alone does not prove the final numeric result for an arbitrary payload.

## Selected output bound

Before the converter writes its success word `0x1a2` and qword at output `+8`, the selected path rejects several nonzero intermediate dwords, rejects a sign-bit-set intermediate word, and rejects an assembled qword above `0x7ffffffffffffffe`. The caller compares the returned word to `0x1a2` and also rejects a zero qword before copying the value to its own output at `+0x10`. Thus on the selected ordinary-success path, the copied raw qword is in `1..=0x7ffffffffffffffe`. This is a bound on the observed integer bit pattern, not a claim of units, source type, rounding rule, or a live asset-registration result. Error and panic helpers are not characterized.

## Evidence and limitations

`instructions.tsv` records the complete converter FDE and selected caller window. `verify.py` authenticates the target digest, two indexed FDE bounds/body hashes, 216 instruction spans, 49 byte pins, seven targets and four relative relocations. Seven arithmetic examples check the scale table and eight controls reject modified anchors. These examples are consequences of the pinned factors, not native execution or a test of the opaque decimal helpers. Reproduce from the repository root using `PYTHONPATH=tools python research/work-items/RE-007-node115-asset-conversion-scale/verify.py` with Capstone installed.

Other scale bytes and mode values, the input text grammar, helper internals, general rounding and decimal representation, allocator/unwind behavior, dynamic execution and cross-version equivalence remain open. No component completion is requested.
