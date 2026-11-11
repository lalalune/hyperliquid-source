# RE-001: node #115 FDE body extent at 0x2d00810..0x2d009ef

- Component: foundation / function map (RE-001).
- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes;
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: what is the authenticated FDE extent, file offset and body digest of
  one bounded `.text` range of node #115, how many objdump lines does that
  range disassemble to, and which byte-supported direct call edge does the
  range contain?
- Claimed window: `0x2d00810..0x2d009ef` (479 bytes), not covered by any
  registered window at the time of selection.
- Ownership: **unknown**. An FDE extent and disassembly do not establish
  function ownership, a source name, or first-party authorship.

## Observed records

| Field | Value | Re-derived by checker |
| --- | --- | --- |
| FDE record | `004f30bc 0000000000000050 0015c994 FDE cie=0039672c pc=0000000002d00810..0000000002d009ef` | presence only |
| FDE start | `0x2d00810` | yes |
| FDE end (half-open) | `0x2d009ef` | yes |
| FDE size | 479 bytes | yes |
| File offset | `0x2cff810` | yes |
| Body SHA-256 | `743cdc0425af36017af36e8e2882b9896eeb29ebe547eb3600368ef4118d99d3` | yes |
| `.text` section | va `0x1419300`, file offset `0x1418300`, size `0x4fd7700` | yes |
| objdump line count | 132 | no (recorded observation) |

The extent comes from the authenticated FDE, not from the next unwind-index
start. The file offset is `text.file_offset + (start - text.va)`.

## Call edge at 0x2d00849

Inside this window the disassembly shows one direct call:

```
 2d00849:	e8 22 14 d2 ff      	call   2a21c70
```

| Field | Value |
| --- | --- |
| Instruction VA | `0x2d00849` |
| Instruction bytes | `e8 22 14 d2 ff` |
| Opcode | `e8` (call rel32) |
| Displacement bytes (LE) | `22 14 d2 ff` |
| Displacement (signed 32-bit LE) | `-0x2debde` (-3009502) |
| Next-instruction VA | `0x2d0084e` |
| Derived target | `0x2d0084e + (-0x2debde) = 0x2a21c70` |

The target is derived from the five instruction bytes alone, not from the
objdump annotation. The callee label is **prior RE-011 interpretation only**:
`research/work-items/RE-011-evm-fee-history-115/functions.json` records
`start_va 0x2a21c70`, `end_va_exclusive 0x2a225bd`, `role=block_number_resolver`,
and that packet states its names are inferences, not recovered symbols. This
edge does not establish which function owns `0x2d00810..0x2d009ef`, what that
function does, or that the callee is reached only from this site.

## Selection rule

First FDE whose extent is not >=90% inside any registered window, searched in
bands `0x2d00000`, `0x3500000`, `0x4500000`, `0x5200000`, `0x5800000`, with a
size bound of 48..512 bytes. The selector printed `covered=no` for this
candidate and `selection_ok: true`.

## Checker and test

Run the checker and its test directly:

```sh
python3 -B tools/foundation_fde_body_2d00810.py
python3 -m unittest discover -s tests -p test_foundation_fde_body_2d00810.py -v
```

- `tools/foundation_fde_body_2d00810.py` authenticates the target digest,
  resolves `.text` with `readelf -S`, checks the window lies inside `.text`,
  re-reads the 479 bytes at the recorded file offset, recomputes the body
  SHA-256, confirms an FDE record exists for the exact pc range, re-reads the
  five bytes at `0x2d00849`, derives the signed little-endian displacement and
  the call target, and then validates the recorded fields in `evidence.json`.
- `tests/test_foundation_fde_body_2d00810.py` runs the actual checker:
  - positive control: the checker passes on the saved packet and prints
    `ok: window 0x2d00810..0x2d009ef` and `ok: call edge 0x2d00849 -> 0x2a21c70`;
  - negative control: a temporary copy of `evidence.json` with
    `window.start` changed to `0x2d00811` makes the checker exit 1 with the
    specific diagnostic `FAIL: evidence window start mismatch`;
  - negative control: a temporary copy of `evidence.json` with
    `call_edge.displacement_decimal` changed to `-3009503` makes the checker
    exit 1 with `FAIL: evidence call_edge displacement_decimal mismatch`;
  - negative control: a temporary copy of `evidence.json` with
    `call_edge.target_va` changed to `0x2cd2990` makes the checker exit 1 with
    `FAIL: evidence call_edge target_va mismatch`;
  - negative control: a temporary copy of `evidence.json` with
    `call_edge.instruction_bytes` changed to `e8 22 14 d2 fe` makes the checker
    exit 1 with `FAIL: evidence call_edge instruction_bytes mismatch`.

### Validation limits

The checker re-derives the target SHA-256, the `.text` section, the window
bounds, the file offset, the body SHA-256, the presence of an FDE for the
exact pc range, and the call-edge numeric and byte fields, and it compares the
recorded `window` and `call_edge` fields in `evidence.json` against those
derived values. It does **not** verify `evidence.json` `target_size_bytes` or
the `text_section` object, it does not recount objdump lines or re-derive the
full FDE record text, and it does not compare the explanatory strings
`call_edge.derivation`, `call_edge.callee_label` or `call_edge.caller_ownership`;
those are recorded observations and prior-research labels.

## Limits

This packet records the authenticated FDE extent, file offset and body digest
of one `.text` range, its objdump line count, and one byte-supported direct
call edge inside that range: the five instruction bytes at `0x2d00849` are
`e8 22 14 d2 ff`, the signed little-endian displacement is `-0x2debde`
(-3009502), and the derived target is `0x2a21c70`. The callee label is prior
RE-011 interpretation only, not a recovered symbol. An FDE, disassembly and
one call edge do not establish function ownership, a source name, or
semantics; the nearest objdump dynamic symbol is not the function identity.
No execution, emulation, caller census or reconstruction claim is made.
