# RE-001: node #115 FDE census for the .text band 0x3a00000..0x3a40000

- Component ID: `foundation` (RE-001 function-map row; work-allocation scope, not a validated #115 function inventory)
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source / base commit: `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation derived from the pinned bytes; one inference is labelled separately below
- Scope included: complete FDEs whose entry VA starts inside `0x3a00000..0x3a40000`, their FDE-derived half-open ends, body lengths, body SHA-256 values and native instruction counts
- Scope excluded: no Rust reconstruction, no raw-equal or normalized comparison, no behaviour, no execution of the target, no whole-module denominator, no progress gate

## Question

Which complete FDEs start inside the 0x40000-byte `.text` band
`0x3a00000..0x3a40000`, and for each one what are the authenticated entry VA,
the FDE-derived half-open end, the body byte length, the SHA-256 of exactly
those body bytes, and the native instruction count - plus which in-band body is
the smallest by byte length and what are its prologue bytes?

The window was screened against existing claims with the host claim gate
before any packet file was written. Function ends here come from the
authenticated FDE pair `pc=START..END`, never from the next unwind-index start.
An FDE start at or above the band end belongs to the following band, and a body
whose start lies below the band start is excluded even when its bytes reach into
the band; the observed failure of the last record's end to fall below
`0x3a40000` is consistent with bounding starts only.

## Reproduce

From the repository root, with GNU readelf/objdump and the pinned capture in
place (the checker reads the target in place and never copies or executes it):

```sh
python3 -B tools/foundation_fde_band3a_census.py
python3 -m unittest discover -s tests -p test_foundation_fde_band3a_census.py -v
make doctor verify test catalogue-check
make reproduce
```

`tools/foundation_fde_band3a_census.py` is the committed checker;
`tests/test_foundation_fde_band3a_census.py` exercises that checker on this
saved packet. Results of commands run for this change are recorded with the
pull request by the host; this README does not assert unrun command results.

## Evidence

All values below are the saved packet records, re-derived from the pinned bytes
at check time:

| Item | Value |
| --- | --- |
| `.text` | VA `0x1419300`, file offset `0x1418300`, size `0x4fd7700` |
| band | `0x3a00000..0x3a40000` (starts only) |
| in-band complete FDEs | 53 |
| first in-band record | `0x3a011d0..0x3a01c63`, 2707 bytes, 630 instructions |
| smallest body | `0x3a15a60..0x3a15d9e`, 830 bytes, 194 instructions, SHA-256 `50b56241a09beea892f37b1139575cd3bb45efa5d9f33d20c6d853ef3dcd2622` |

Within this section a VA maps to file offset `VA - 0x1000` (offset `0x1418300`
at VA `0x1419300`), which is how each body is read for hashing. Every in-band
record as saved in `frames.txt` names CIE `cie=0039672c`; the smallest body's
readelf record begins `0058acec`, with the remaining fields exactly as saved.
The 53 record rows, their frame lines and their hashes are in `evidence.json`
and `frames.txt`.

The smallest body's saved objdump excerpt (`window.txt`) starts at
`0000000003a15a60` and its first bytes are `41 57 41 56 53 48 81 ec b0 00 00 00`
(`push %r15`, `push %r14`, `push %rbx`, `sub $0xb0,%rsp`). The same excerpt
contains direct calls to `0x3b67580` and `0x3d63760`; both targets lie outside
the band and were not analysed. The excerpt's symbol label is objdump's nearest
exported dynamic symbol used as an anchor, not a body at or next to the window.

Inference (not established by these bytes): the observed dispatch on the low
byte at `(%rdi)` against `0x14`/`0x15`, followed by fixed-size loads and stores,
is consistent with tagged-value or variant handling. What the body computes, its
callers, its callees and its data types remain unknown.

No upstream dependency window is claimed or counted. No `std::`, `core::`,
`ZSTD` or libc body is present inside or adjacent to the measured windows; only
objdump's far-away anchor label mentions a libstdc++ symbol, so this packet
contributes nothing to a dependency table and all 53 records are first-party
target bytes pending ownership review.

## What the checker independently derives

The committed checker authenticates the target size and SHA-256, reads the
`.text` coordinates from `readelf --wide --section-headers`, collects FDE rows
from `readelf --wide --debug-dump=frames`, keeps rows whose start lies in the
band, requires non-empty, strictly increasing and mutually disjoint ranges
inside `.text`, then for every kept row seeks to the section file offset, reads
exactly `END - START` bytes, and re-computes the body SHA-256 and the native
instruction count from `objdump -d` over that range. It rejects saved records
whose start, end, length, digest or count differs from the re-derived value,
rejects a `frames.txt` that is not exactly the derived FDE lines, rejects a
`window.txt` whose prologue byte tokens do not match the target bytes at the
smallest record's start, and verifies each host-written `MANIFEST.sha256` entry
against the saved file bytes and against the actual file set.

The focused test runs that checker on this packet and adds corruption
controls: reversed range, duplicate start, overlapping range, out-of-band
start, missing and reordered frame lines, changed window prologue, missing
window, tampered body digest, changed end, changed length, tampered and zero
instruction counts, fabricated start and duplicated record - plus acceptance of
the saved records unchanged. A scratch verifier pass alone is not treated as
proof that the committed checker runs.

## Implementation and comparison

Not applicable and not yet measured: this packet contains no Rust
implementation, no byte-window registration and no raw-equal or
normalized-only comparison. Zero registered comparisons is a count, not a
claim about correctness of any code.

## Results and limitations

Measured denominator for this packet: 53 complete FDEs starting in
`0x3a00000..0x3a40000`, each with a re-derived end, body length, body digest and
instruction count. No progress gate is requested; all component gates remain
false.

Limits. Static analysis only: the target was never executed, emulated or
copied, and no behaviour is claimed. The FDE extents are the compiler's unwind
descriptions; they are not a proof that every byte in a range belongs to one
logical source function, and no function name, type, signature or source
mapping is recovered here. Instruction counts are objdump's decoding of those
bytes. Nothing in this band is compared against a build, so no equivalence,
safety or compatibility claim is made. The band is one 256 KiB slice of
`.text`; it supplies no whole-module denominator.

Next step: extend the census to a neighbouring band only after the existing
claim gate confirms it is unclaimed.
