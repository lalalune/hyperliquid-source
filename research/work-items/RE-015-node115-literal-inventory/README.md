# RE-015: node #115 `hl-node` literal inventory

- Component ID: constants (`global_constants/*`); depends on foundation.
- Task row: RE-015 (P2) - digest-bound #115 literal inventory and pool-entry
  xrefs. This packet requests **no progress gate**.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Job base commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Claim status: observation from the pinned static bytes only.
- Captured code executed: false. The target is read in place, never executed,
  copied or modified.

## Exact question

Which bytes of the pinned node #115 image contain the ASCII token `hl-node`
(raw bytes `68 6c 2d 6e 6f 64 65`, length 7), at which virtual addresses and file
offsets, in which allocated sections, and does any `R_X86_64_RELATIVE` entry in
`.rela.dyn` have an addend equal to one of those addresses - that is, is the
literal referenced from a relocated data slot rather than reached only by a
RIP-relative load?

## What the bytes show

Section bounds derived from the ELF section table of the pinned file
(virtual address range, file offset, size):

| Section | VA range | File offset | Size |
| --- | --- | ---: | ---: |
| `.rodata` | `0x430400..0xb9ea40` | `0x430400` | 7,792,192 |
| `.data.rel.ro` | `0x63f3c20..0x64df248` | `0x63f1c20` | 964,136 |
| `.data` | `0x64efa20..0x64ffe08` | `0x64eca20` | 66,536 |

`.rela.dyn` holds 60,723 entries, of which 59,534 carry relocation type
`R_X86_64_RELATIVE`.

A plain byte search of the three sections above (single-byte advance, so
overlapping matches are counted) finds **5** occurrences of `hl-node`. The
checker records the first three in address order, and every recorded occurrence
is in `.rodata`:

| VA | File offset | Section | Bytes | Relative slots |
| --- | --- | --- | --- | ---: |
| `0x434a3e` | `0x434a3e` | `.rodata` | `686c2d6e6f6465` | 0 |
| `0x440f36` | `0x440f36` | `.rodata` | `686c2d6e6f6465` | 0 |
| `0x605ccd` | `0x605ccd` | `.rodata` | `686c2d6e6f6465` | 0 |

"Relative slots" counts `R_X86_64_RELATIVE` entries whose addend equals that
virtual address. All three recorded occurrences have zero, so these bytes are
**not** named by a relative relocation in this image. The remaining two
occurrences are counted in the total but are not itemised in `evidence.json`.

## Packet contents and reproduce

Files: `README.md`, `evidence.json`, `MANIFEST.sha256` (written by the workbench
host from the saved bytes), `tools/foundation_literal_inventory.py` (the
checker, which re-derives every recorded value from the pinned bytes and runs
in-memory corruption controls) and `tests/test_foundation_literal_inventory.py`
(the committed test that exercises that checker on this saved packet).

```sh
python3 -B tools/foundation_literal_inventory.py
python3 -B -m unittest tests.test_foundation_literal_inventory -v
```

The checker asserts the pinned SHA-256 before and after the read, derives the
section bounds, the `.rela.dyn` counts and the literal occurrences itself, and
compares them field by field with `evidence.json`. Eight corruption controls
mutate a derived copy in memory (literal bytes, an occurrence address, a
claimed relative slot, the occurrence count, the relative relocation count, a
section bound, the target digest, the execution flag); each mutated copy must
be rejected by the comparator.

## Results and limits

Measured denominator: 3 allocated sections, 1 literal token of length 7, 5
occurrences, 60,723 `.rela.dyn` entries and 59,534 relative relocations, over
the single authenticated #115 file.

Limits:

- Static byte evidence only. Nothing here establishes that these strings are
  used as a program name, a network name, a default value or any other
  semantic; the token's meaning is not claimed.
- Absence of a matching `R_X86_64_RELATIVE` addend is not a complete cross-
  reference census. No instruction site, RIP-relative load, data descriptor or
  caller is recorded or attributed in this packet yet; that is the next
  question.
- The search covers only `.rodata`, `.data.rel.ro` and `.data`; other sections
  and the string tables are outside this inventory.
- No runtime behaviour, no execution of the captured binary, no network or
  chain action, and no codec or format inference from these bytes.
- The checker compares recorded fields against bytes; it is not an emulator and
  does not validate any reconstructed implementation.
- No command result is asserted in this file. The workbench host runs and
  records the required checks; this packet claims none of their outcomes.

Next question: which instruction or data site actually consumes the bytes at
`0x434a3e`, `0x440f36` and `0x605ccd`, recorded from the authenticated FDE and
objdump of the enclosing function.
