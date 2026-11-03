# RE-001: node #115 complete-FDE census of the .text window 0x1a00000..0x1a40000

- Task: RE-001 (#115 function map). Component allocation: foundation utilities.
- Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  whole ELF 105,896,032 bytes as recorded in the generated `docs/PROGRESS.md`.
- Coordinates: ELF virtual addresses (VA) of the pinned file, half-open ranges.
- Question: how many functions have their complete authenticated FDE inside
  `0x1a00000..0x1a40000`, which is the smallest such function, and what are its
  exact FDE extent and body SHA-256?

## Why this window

The region is an unworked part of `.text`: no retained packet name in
`research/work-items/` and no open pull-request title cites an address inside
`0x1a00000..0x1a40000`. The bounded question is therefore new #115 work rather
than a repeat of a covered window.

## Method (static bytes only)

`tools/foundation_unworked_leaf.py` reads `artifacts/node/115/hl-node` in place
and authenticates the SHA-256 above before any analysis. It then parses the
ELF64 section table and every `.eh_frame` CIE/FDE record from the pinned bytes
without binutils:

- each FDE end comes from the FDE's own range field under its CIE's encoding,
  never from the next unwind-index start;
- CIE augmentation `zPLR` is decoded, including pcrel/sdata4 pointers;
- truncated records, an unparsed CIE, unsupported encodings, records that
  overrun their own length and an empty window are rejected, not accepted;
- `window.txt` instruction bytes are re-checked against the target bytes.

## Recorded observations

From the recorded verifier run at base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`:

| Field | Value |
| --- | --- |
| `target_sha256` | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| `fde_total` | 135313 |
| `fde_in_0x1a00000_0x1a40000` | 67 |
| `fde_le_120_bytes` | 0 |

Consequence: the initial premise of a small leaf of at most 120 bytes has no
member in this window, so this packet does not claim one. It records the
window's complete-FDE census (67 records) and selects the smallest complete
function by authenticated FDE extent, binding that extent to its body digest.
That is the honest bounded result here: a census plus one body binding, not a
leaf claim and not a function-boundary guess.

## Packet schema

| File | Role |
| --- | --- |
| `tools/foundation_unworked_leaf.py` | committed checker; `--emit` prints the exact derived JSON block |
| `tests/test_foundation_unworked_leaf.py` | runs the checker on the saved packet plus corruption controls |
| `evidence.json` | the derived block verbatim, target identity and limits |
| `frames.txt` | the observed FDE lines for the 67 in-window records |
| `window.txt` | optional objdump excerpt of the selected function; the checker re-checks its instruction bytes against the target only when the file is present |
| `MANIFEST.sha256` | written by the host from the saved bytes, never by hand |

Every derived number (`.eh_frame`/`.text` geometry, CIE count, encodings, the
selected start/end/extent and its body SHA-256, and the per-record digest list)
is produced by the checker from the pinned bytes. This README restates only the
four values that an actual recorded run printed; it does not restate derived
values that have not been observed in a recorded run.

## Reproduce

```sh
python3 -B tools/foundation_unworked_leaf.py --emit
python3 -B tools/foundation_unworked_leaf.py
python3 -B -m unittest discover -s tests -p test_foundation_unworked_leaf.py -v
make doctor verify test catalogue-check
make reproduce
```

A listed command is not a claim that it ran for this packet; the results that
were actually observed are reported with the pull request.

## Limits

- Static parsing of the pinned bytes only. The captured binary is never
executed, copied, relocated or introspected at runtime; no network, chain,
signing or key material is involved.
- 67 complete FDEs in one window are not the function inventory of the binary
and this window is not a statement of component ownership.
- No xref, caller, data-layout or semantic claim is made about the selected
body; what the code computes is unknown here.
- Whether an upstream dependency symbol (for example a `std::`, `core::` or
`ZSTD` symbol) is named at or next to this window is not asserted in this
file. If objdump shows one, the packet records that dependency identity and
counts it only in target totals and the dependency table, never as
reconstructed first-party component bytes.
- No reconstruction completion gate is advanced; all component gates stay
false.

## Next step

Close the selected body's direct callers and data references, then repeat the
same census in the adjacent unworked windows so the #115 function map grows by
recorded FDE extents rather than by inferred boundaries.
