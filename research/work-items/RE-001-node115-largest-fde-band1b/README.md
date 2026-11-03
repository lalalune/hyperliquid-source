# RE-001: node #115 largest complete FDE in the `.text` band 0x1b00000..0x2000000

- Component: Foundation / node `#115` function map (`docs/TASKS.md` RE-001).
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`; 105,896,032 bytes;
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (integration branch `main`).
- Question: which complete FDE is the largest whose entry address lies in the
  `.text` band `0x1b00000..0x2000000`, and what are its exact FDE-derived extent
  and code-byte digest?
- Recorded answer: entry `0x1d7f620`, half-open extent `0x1d7f620..0x1d9243f`,
  77,343 bytes, file offset `0x1d7e620`, body SHA-256
  `7183b9de5bf56bb92e9ac042d79d2bae620eaad91c549e5ef9601b575b605bc2`.

Every value below is copied from the job's recorded verifier output or the
saved packet files, and the committed checker re-derives it from the pinned
bytes. No value is taken from a symbol name, comment or upstream source alone.
The captured executable is never run, copied or modified.

## Binary identity and address coordinates

The target digest and size are checked before any record is decoded. Addresses
are ELF virtual addresses; a `.text` file offset is
`text.offset + (va - text.va)`, and `.eh_frame` is stored at its link address.

| Section | VA | File offset | Size |
| --- | ---: | ---: | ---: |
| `.text` | `0x1419300` | `0x1418300` | 83,719,936 |
| `.eh_frame` | `0xca6ed8` | `0xca6ed8` | 7,803,772 |

## Recorded observations

Decoded statically from the pinned `.eh_frame` bytes:

- The section holds 3 CIEs and 135,313 FDEs.
- The `.text` band `0x1b00000..0x2000000` holds 3,437 FDEs whose entry address
  lies in the band and whose recorded extent is non-empty. The chosen FDE is
  the largest among those that also end inside `.text`.
- The chosen FDE record sits at `.eh_frame` offset `0x408068` and occupies 108
  bytes (`0000006c`), referencing CIE record `0x39672c` with augmentation
  `zPLR` and FDE pointer encoding `0x1b` (`DW_EH_PE_pcrel | sdata4`).
- The frame row derived from those bytes is:

```text
010aef40 0000006c 0039672c FDE cie=0039672c pc=0000000001d7f620..0000000001d9243f
```

- The first 160 bytes of the chosen extent (the excerpt length used by both the
  checker and the job verifier) are:

```text
55 41 57 41 56 41 55 41 54 53 48 81 ec 00 10 00 00 48 c7 04 24 00 00 00 00 48 81 ec 00 10 00 00 48 c7 04 24 00 00 00 00 48 81 ec 00 10 00 00 48 c7 04 24 00 00 00 00 48 81 ec 00 10 00 00 48 c7 04 24 00 00 00 00 48 81 ec 00 10 00 00 48 c7 04 24 00 00 00 00 48 81 ec d8 0d 00 00 48 89 bc 24 88 00 00 00 48 b8 00 00 00 00 00 00 00 80 48 89 b4 24 20 05 00 00 c6 84 24 28 05 00 00 01 48 c7 84 24 20 43 00 00 02 00 00 00 48 89 84 24 b8 01 00 00 48 89 84 24 d0 01 00 00 48 89 84 24 e0 2d
```

## Runner-up candidates

The ten largest complete in-`.text` FDEs of the band, ordered by extent, with
record offsets inside `.eh_frame` and the SHA-256 of each FDE-derived body:

| # | Half-open extent | Bytes | FDE record | Body SHA-256 |
| ---: | --- | ---: | ---: | --- |
| 1 | `0x1d7f620..0x1d9243f` | 77,343 | `0x408068` | `7183b9de5bf56bb92e9ac042d79d2bae620eaad91c549e5ef9601b575b605bc2` |
| 2 | `0x1d793e0..0x1d7f619` | 25,145 | `0x408014` | `b61907d78b96b2451f187bebbc48e32745b259fd8921bc0d28b1938f819ab1c2` |
| 3 | `0x1beb080..0x1bf03eb` | 21,355 | `0x3fc1cc` | `85c3db1daf89c42beba525091139f13c9a45a8ad8849c3694406c04d28b43850` |
| 4 | `0x1c14a50..0x1c19bd5` | 20,869 | `0x3fcc2c` | `4ff2702e4e47268f5b971bbe44bff19a9cb559468ee2d555a483c572b105533f` |
| 5 | `0x1c1e610..0x1c23558` | 20,296 | `0x3fcdcc` | `8477bbf45c0e169511f7b2e7636436048823b98b39df4e6b23d24e87133a6ef1` |
| 6 | `0x1f5e410..0x1f62ecc` | 19,132 | `0x41fd30` | `1389818585a4c12e0c2a852ff75abacfa690577a7057f0506761f9e4abe61d39` |
| 7 | `0x1e7a3e0..0x1e7eb37` | 18,263 | `0x41bb58` | `df6a429f13c852a2906963ac6895c559765f50bc8b51719272bc85dd195f83a0` |
| 8 | `0x1e54850..0x1e58f97` | 18,247 | `0x41b128` | `7e47475d565ecf25c168155992404dcc779ba06b56c787a075e333cd90f7aaad` |
| 9 | `0x1f7e100..0x1f82681` | 17,793 | `0x420664` | `6a8a64a57bd3c13c758bacecab6bdee9cac9d503780013cd0eed4fb0b588f38e` |
| 10 | `0x1ed4320..0x1ed86ed` | 17,357 | `0x41d4ac` | `ddd97f4db968be2e4c7fe76d994086f5c61ef0c9646cbef0d924268d7d705d34` |

Observation from the two recorded extents: the runner-up ends at `0x1d7f619`
(exclusive), seven bytes below the chosen entry, so the six bytes
`0x1d7f61a..0x1d7f61f` are covered by neither of these two extents. Whether
another FDE covers them is not asserted here.

## Inferences kept separate from observations

1. The leading bytes are `push`/`mov` setup followed by five `sub $0x1000,%rsp`
   probe steps with `movq $0x0,(%rsp)` stores and a final `sub $0xdd8,%rsp`.
   That is consistent with a large-frame function prologue that probes guard
   pages; it is an inference from the byte pattern, not a behavior claim.
2. objdump labels the window start
   `_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3fc8e10`. That notation means the nearest
   preceding dynamic symbol `_ZNKSt5ctypeIcE8do_widenEc@@Base` (a libstdc++
   `std::ctype<char>::do_widen` mangling) lies `0x3fc8e10` = 66,883,088 bytes
   after the window start, far outside it. The label therefore identifies a
   nearest preceding symbol only; it does not place a std:: or other dependency
   at or next to this window. No dependency attribution or dependency-table
   entry is made, and all 77,343 bytes are recorded as un-attributed target
   bytes, not as reconstructed first-party or dependency bytes.
3. No function name, crate, source path or semantic role is inferred for this
   window; the extent comes only from the authenticated FDE.

## Reproduction

From the repository root, with the pinned capture materialized:

```sh
python3 -B tools/foundation_largest_fde_band1b.py
python3 -B -m unittest discover -s tests -p test_foundation_largest_fde_band1b.py -v
```

The checker reads `artifacts/node/115/hl-node` in place, re-derives the section
coordinates, the CIE/FDE census, the band count, the chosen extent, the body
digest and the ten candidate rows, and compares them with its recorded
constants. Its corruption controls re-run the band census with a different
upper bound, replace the chosen extent with one byte, mutate a byte inside the
window and tamper with the frames row, and require each to be rejected. The
committed test runs the actual checker (including a subprocess run of its CLI),
pins the recorded literals independently, and requires a missing target to fail
closed. `MANIFEST.sha256` is written by the job host from the saved bytes, not
by hand.

## Limits

Static byte evidence for one band and one selected FDE only. The captured node
was not executed, so no runtime behavior, call target, layout or semantic role
is claimed. There is no complete xref, caller or callee census, no whole-module
function denominator (the 77,343 chosen bytes are 0.09% of `.text` and are one
validated window, not a module measurement), and no reconstruction-gate credit:
all component gates stay false. The objdump excerpt was produced inside the
job's validation container; its version string was not captured in that output,
so no tool-version claim is made here. Whether a differently bounded band would
select another FDE is not claimed. Next step: recover the callers or callees of
this window from independent #115 evidence before assigning any semantics.
