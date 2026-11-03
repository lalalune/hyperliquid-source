# RE-001: node #115 .eh_frame CIE identity and FDE start/extent census

- Component: RE-001 (#115 function map) - unwind metadata census only.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Claim status: observation, derived only from the pinned target bytes. Nothing in this packet was executed.
- Scope included: the CIE records of `.eh_frame`, their augmentation and pointer-encoding fields, their record digests, the per-CIE FDE counts, the section terminator offset, and a census of FDE start addresses and recorded extents.
- Scope excluded: function names, source or crate attribution, instruction semantics, call/relocation analysis, dependency-versus-first-party attribution of any FDE, and every reconstruction gate.

## Question

Which CIE records support the node #115 `.eh_frame`, and what start-address and
extent census do their FDEs give?

The purpose is narrow: before any function-range work can cite an FDE, the
unwind metadata that produces those ranges must be identified and its census
must be reproducible from the target bytes alone.

## Reproduce

Static parse only. The target is read in place at
`artifacts/node/115/hl-node`; it is never copied, executed, emulated or reached
over a network. Python 3 (`python3 -B`) on the project workspace, with
`hashlib`, `struct`, `json` and `pathlib` from the standard library and no
third-party dependency.

```sh
python3 tools/foundation_ehframe_cie_census.py --derive   # print derived values
python3 tools/foundation_ehframe_cie_census.py            # compare with evidence.json
python3 -m unittest discover -s tests -p test_foundation_ehframe_cie_census.py -v
```

The checker first authenticates the target size and SHA-256, then parses the
section table, reads the `.eh_frame` bytes by their recorded file offset, and
re-derives every value below. A mismatch, a missing packet file or a corrupted
input exits 1 with a reason. Corruption controls alter a CIE record digest, a
per-CIE FDE count, the extent total, the terminator offset, the lowest start
address, the target size and the target digest; each mutation must be rejected
twice (recorded copy versus derived copy, and the authentication gate).

## Evidence

All addresses are ELF virtual addresses; for this file the `.eh_frame` file
offset equals its VA because the section is in the first loadable segment.

Section facts as parsed from the target:

| Field | Value |
| --- | --- |
| `.eh_frame` VA | `0xca6ed8` |
| `.eh_frame` file offset | `0xca6ed8` |
| `.eh_frame` size | 7,803,772 bytes |
| CIE records | 3 |
| FDE records | 135,313 |
| section terminator (zero length word) offset, relative to section start | `0x771378` |
| `.text` VA | `0x1419300` |
| `.text` size | 83,719,936 bytes |

### CIE records

| # | section offset | version | augmentation | code align | data align | RA reg | FDE pointer encoding | LSDA encoding | personality encoding | personality VA | FDEs | record SHA-256 |
| --- | --- | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- | ---: | --- |
| 1 | `0x0` | 1 | `zR` | 1 | -8 | 16 | `0x1b` | absent | absent | absent | 82,631 | `78b6da08ece7423d48f0be866ea3d8c0b62f6b7053852a71a7672b490842354f` |
| 2 | `0x39672c` | 1 | `zPLR` | 1 | -8 | 16 | `0x1b` | `0x1b` | `0x9b` | `0x64efa28` | 48,005 | `9e6e9615ae59244ee5831acac36746f21d8a6be07b7aa0468edb6c0bed2de386` |
| 3 | `0x730230` | 1 | `zPLR` | 1 | -8 | 16 | `0x1b` | `0x1b` | `0x9b` | `0x64fee68` | 4,677 | `32b7fa3622428fc1494becaf845beafb51e17cb51961a1121e53044127c2ffe9` |

Every record digest above is the SHA-256 of the raw CIE record bytes, length
word included. The raw bytes are kept in `cie-records.txt`:

```text
0x0      1400000000000000017a5200017810011b0c070890010000
0x39672c 1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000
0x730230 1c00000000000000017a504c5200017810079b4d7d12051b1b0c070890010000
```

The three augmentations are distinct personalities: one CIE has no
personality and no LSDA, and the other two carry `zPLR` with LSDA encoding
`0x1b` and personality encoding `0x9b`. Two different personality addresses are
recorded (`0x64efa28`, `0x64fee68`); which routine or dependency each slot
resolves to is **not** established here.

### FDE census

| Field | Value |
| --- | ---: |
| FDE records | 135,313 |
| distinct start addresses | 135,313 |
| start addresses appearing more than once | 0 |
| start addresses inside `.text` | 135,313 |
| start addresses outside `.text` | 0 |
| sum of recorded FDE extents | 82,661,417 bytes |
| FDEs whose extent overlaps the previous extent | 0 |
| lowest start address | `0x1419300` |
| highest start address | `0x63f09f0` |
| SHA-256 of the newline-joined ascending distinct starts (hex, no `0x`) | `d280117ade486efbb52103a242dfd63a18108634fab3ad68bba1bf13fabce32d` |

The per-CIE FDE counts sum exactly to the 135,313 records. The lowest FDE start
equals the `.text` VA, and the highest start lies `0x4fd5cf0` above it. Because
no two recorded extents overlap, the extent sum is the union of the extents;
that union is 1,058,519 bytes smaller than `.text`, so some `.text` bytes lie
outside every recorded FDE extent. This packet does not enumerate those gaps.

The first ten distinct starts and their extents are kept in `fde-census.txt`,
together with the census table above, so the excerpt can be compared byte for
byte with the checker output.

## Implementation and comparison

Not applicable. No Rust reconstruction, no comparison against a source build and
no byte-window registration is proposed. `.eh_frame` is metadata about code; it
does not establish any function body, and no alignment, normalization mask or
matched-window denominator is claimed.

## Results and limitations

What the bytes show: `.eh_frame` contains exactly three CIE records and 135,313
FDE records, the parse reaches a zero length word at section offset `0x771378`,
every FDE start is distinct and lies inside `.text`, and the recorded extents do
not overlap.

Limits:

- Static parse only. The target was not executed, traced, emulated or copied,
  and no network, chain, signing or dataset action was performed.
- FDE extents are taken from the FDE records themselves. This packet does not
  prove that an FDE extent equals a function body, and it does not treat the
  next FDE start or an unwind-index entry as a function end.
- FDE starts are not function entry points here; no names, source paths, crate
  ownership, dependency identity or first-party component bytes are assigned.
- `.eh_frame` covers unwind metadata for code from more than one origin; this
  packet attributes none of it, so no dependency window and no reconstructed
  first-party window is claimed.
- No component gate, progress record or catalogue entry is requested or changed.
- Corruption controls show that the specific recorded fields are checked. They
  are not a proof that arbitrary byte corruption anywhere in the target would be
  detected.

Next question: for a bounded FDE selected from this census, does the recorded
extent agree with an independently derived end from the same record, and which
callers reference that start address through the relocation and call data?
