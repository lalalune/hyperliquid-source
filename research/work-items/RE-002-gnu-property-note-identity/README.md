# RE-002: GNU property-note identity survives a section rename

- Task/component: build-provenance tooling; no catalogue component gate.
- Target context: node94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Node115 and visor are compatibility checks, not this target.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Claim status: observed ELF metadata and a reproduced ordinary tooling defect.
- No inferred reference source was used or copied. No captured or control ELF
  was executed. No target compile setting, CPU capability or runtime behavior
  is inferred from the controls.

The old `elf.has_gnu_property_note` fact tests only the section name
`.note.gnu.property`. GNU objcopy can rename that section while retaining its
SHT_NOTE type, GNU owner/type-5 record, bytes and PT_NOTE/PT_GNU_PROPERTY mapping.
GNU readelf still recognizes the property note, but the old fact becomes false.
Its absence explanation therefore disagrees with actual supported note data.

The fix recognizes owner `GNU\0` and `NT_GNU_PROPERTY_TYPE_0` (5) in bounded,
file-backed SHT_NOTE records. It honors four/eight-byte note alignment and checks
header/payload spans. A conventional name on a PROGBITS section or a different
note owner/type is insufficient. Property descriptor bits are not interpreted.

## Reproduce

With the pinned repository inputs and existing GNU GCC/binutils tools available,
run from the repository root. The work path must be new; earlier evidence is
preserved if the path already exists.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-002-gnu-property-note-identity/probe.py --work work/gnu-note-control
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_gnu_property_note_provenance.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/build_provenance.py --check
make doctor verify test catalogue-check reproduce
sha256sum -c research/work-items/RE-002-gnu-property-note-identity/MANIFEST.sha256
```

`probe.py` extracts the actual base helper from the pinned Git commit and verifies
its SHA-256 before importing it. It compiles one independently authored one-line
C fixture, then uses GNU objcopy to rename only its property section. The
fixture-only linker option `-z ibt` guarantees a property note for this control;
it is not a hypothesis about the captured node's flags or execution environment.
Neither generated ELF is run. Their work files are mode0600 in a mode0700 work
directory; no binaries or copied base source are committed.

Observed environment: Python3.12.14, GCC14.2.0 (Debian14.2.0-19), GNU objcopy and
readelf2.44. `CONTROL.json` preserves exact commands, versions, fixture source,
file/note hashes, program-note mappings and both helpers' facts. Fixture hashes
bind this observed compiler/linker run. Native exports in `raw/` are unchanged.

## Evidence

The actual GCC control contains a 48-byte GNU property note. Renaming its section
to `.note.provenance-control` leaves all 48 note bytes identical, SHA-256
`5c4eadc048677e9201f774c7be11e1cde333dea63bbb7566e92d0865cab26468`.
Both PT_NOTE and PT_GNU_PROPERTY continue to describe the same note interval.

| Control | GNU readelf note | Base fact | Corrected fact |
| --- | --- | --- | --- |
| Conventional section name | GNU type5 property | true | true |
| Renamed section | Same GNU type5 property | false | true |

The parser uses the actual note records, not raw byte-pattern scanning. The
separate combined-note control has a 36-byte build-ID note, four bytes of
alignment padding and a later 32-byte property note. GNU readelf independently
recognizes both records (`raw/combined-note.readelf.txt`). This checks the
eight-byte record boundary rather than assuming the property is first.

`TARGET94.json` binds the actual node94 note context to its full artifact digest.
Its one PT_NOTE covers file `[0x2fc,0x340)`: `.note.ABI-tag` and
`.note.gnu.build-id`. There is no property note in these records. The node94
fact remains false; there is no claimed mismatch in the captured target.
ABI-tag words and the build-ID bitstring do not identify the original host,
compiler options or minimum supported runtime.

## Implementation and comparison

`tools/build_provenance.py` adds one note-identity helper and replaces the single
name-membership test. It does not change stripping inference (#979), version
requirement attribution (#985), duplicate-section handling (#984), dependency
paths or any decoder/implementation. Four new regression methods cover:

1. Conventional and renamed SHT_NOTE property records.
2. A name-only PROGBITS decoy, a different owner and a different note type.
3. The later property record after an eight-byte-aligned earlier note.
4. A descriptor extending outside its own section.

All four methods fail with the actual unchanged base helper (six subtest
failures, no errors), then pass with the correction. `BASE-TESTS.json`,
`base-tests.log` and `fixed-tests.log` retain the actual results. The nine existing
build-provenance tests also pass, including regeneration from all three verified
captures. `CAPTURED-RECORDS-UNCHANGED.json` records an additional exact-byte
comparison of each serialized saved record; none changes.

No original ELF bytes, signatures, imports, source pins, catalogue or progress
files change. No Rust reconstruction, target rebuild, normalization mask,
runtime comparator or completion credit is requested. Required whole-repository
results are reported separately for the exact frozen publication commit.

## Results and limitations

The supported detection scope is file-backed SHT_NOTE records in the existing
ELF64-LE section-table parser. The fact and its absence annotation are scoped to
that metadata. This change does not add segment-only ELF support or infer
loader-wide property absence, CET activation, IBT/SHSTK availability, target CPU
features or build flags. A true property-note fact does not say which property
bits are set. All reconstruction gates remain unchanged.

Next question: can the original build configuration or a matched source build
explain the captured note inventory? That evidence is still unavailable; the
fixture's linker option supplies no answer about the original build.
