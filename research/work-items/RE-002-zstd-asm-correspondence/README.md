# RE-002: licensed assembly correspondence for two selected capture intervals

- Component: build provenance / native dependency source constraints.
- Node #94: 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Node #115: 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Maintained source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Claim: observed compatible licensed source/configuration, partial RE-002.
- No original archive/fork/crate/version/compiler attribution or progress gate.

## Question and result

Can a pinned, licensed upstream source and a measured real toolchain generate
all bytes of the two selected no-FDE code candidates? What does a neighboring
official release or a genuine CET-disabled configuration tell us about that
source constraint?

| Candidate | #94 linked VA | #115 linked VA | Bytes per target |
| --- | --- | --- | ---: |
| A | `[0x5631580,0x56319fd)` | `[0x62e4700,0x62e4b7d)` | 1,149 |
| B | `[0x56319fd,0x5631ef2)` | `[0x62e4b7d,0x62e5072)` | 1,269 |

The exact unmodified licensed Zstandard `v1.5.6` assembly and real header,
with the recorded GNU/CET recipe, emit all **2,418 selected code bytes** exactly
in both admitted captures. Two unchanged builds produce identical 3,408-byte
ET_REL objects. Their actual X1/X2 labels are hidden GLOBAL/NOTYPE aliases
with size zero, at offsets 0 and 1,149. The exact `.text` end is 2,418; no
symbol sizes, padding trims, byte masks or target-derived compiler inputs are
invented. There are no text relocations or `.eh_frame` in these own objects.

The source-defined labels are
`HUF_decompress4X1_usingDTable_internal_fast_asm_loop` and
`HUF_decompress4X2_usingDTable_internal_fast_asm_loop`, plus underscore aliases.
The observation identifies a compatible source recipe for these spans. It
does not establish which archive, fork, commit, flags or original symbol names
were historically used to build either captured executable.

The explicit CET-disabled control uses the same unmodified 1.5.6 inputs and
one changed compiler option. Its full `.text` remains 2,418 bytes, with 281
different byte positions in A and 276 in B per target. All four selected
comparisons reject it; every mismatch is retained. A length-only check would
miss this distinction.

Official 1.5.7 has different assembly/header source blobs. Under the measured
non-Windows Linux configuration, its complete compiler-produced `-E -P`
assembly is byte-identical to 1.5.6: 13,374 bytes, SHA-256
`2ed4575150c42442e039fbbf86f3dd1251fc3cacc78b78db2f6e5ed898b662e1`.
No 1.5.7 object is built and no object hash is inferred. This records version
ambiguity in the active input, not a unique original 1.5.6 dependency claim.

## Reproduce

This packet qualifies one exact Linux x86-64 environment: Debian GCC
14.2.0-19, GNU Binutils 2.44, the recorded cc1/assembler/providers and actual
GCC/glibc header identities. The collector pins their full hashes before
building and refuses unsupported identities explicitly. It installs nothing,
chooses no fallback flags or SDK, and does not identify that installed compiler
as the original Ubuntu GCC 13.3 stamp observed elsewhere in the captures.

From the repository root with existing pinned captures and source submodules:

```sh
mkdir -p /tmp/hlzstd work
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/hlzstd python3 -B \
  tools/zstd_asm_correspondence.py --output-dir work/zstd-asm-fresh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/hlzstd python3 -B -m unittest discover \
  -s tests -p test_zstd_asm_correspondence.py -v
make --jobs=1 'PYTHON=python3 -B' doctor verify test catalogue-check reproduce
```

Use a fresh output directory. Existing output is refused before admission;
incorrect input produces no new evidence directory. On an unsupported native
host the direct collector fails explicitly. The native-dependent test class
reports a clear skip there; a skip does not qualify this correspondence.
Normal and optimized focused results and the final exact-commit checks are
reported separately. No hosted CI or container success is implied.

## Evidence and method

The two exact licensed source/header/LICENSE triples are retained under
`third_party/`, with their original rights, immutable upstream commits and
blob hashes in `UPSTREAM.json`. They are compiled offline. No unlicensed
inferred reference source is read or copied. System header source is not
vendored; actual license notices and hashes are recorded as toolchain data.

Every target and licensed input is admitted as immutable bytes. Target
section/PT_LOAD facts and reference slices derive from that same admitted
object, with unique agreeing file/VA mappings. Source snapshots alone are
written to new owned staging directories under physical `/tmp`; captured
bytes are never compiler inputs. Actual CPP macros, dependencies and expanded
assembly are recorded before the single recipe for each build.

The source/header/tool identities and actual header closure are pinned. Real
GNU default macros enable the BMI2 assembly; actual `cet.h` supplies ENDBR64
under `__CET__ == 1`. No stub header or invented `-D` definitions are used.
The installed toolchain/system headers are trusted stable inputs checked
before and after. This is not an atomic execution-provenance guarantee.

Each compiled own object is read once into immutable bytes. All object ELF,
symbol, text, relocation and comparison facts use that snapshot. GNU native
providers receive only a fresh tiny copy of that own object; their complete
instruction bytes/addresses and exported text must bind the admitted snapshot.
Original capture paths are never native-provider inputs. No object, captured
executable or emulator is executed, and no executable is linked.

`evidence/collector/REPORT.json` records all comparisons, input/source/helper/tool
hashes and exact mismatch arrays. Its `COMMANDS.json` records invoked argv and
environment; workdirs are explicitly relative to the private staging root.
The exact process TMPDIR value is `tmp`. Raw compiler/native streams are
preserved. Historical prototype `cc -###` logs were dry-run configuration
previews, not executed process-tree traces; the collector makes no such trace
claim. Output bytes are deterministic on the same qualified inputs/toolchain.

The collector evidence contains three newly built own ET_REL objects and their
raw text, metadata and native listings. Separate test-control evidence retains
20 corrupted copies of own objects and two corrupted native listings, all
rejected. These input-data fixtures are not additional compiler builds. The
BSD source rights remain attached; none is committed as Rust or original-node
recovery. The collector `OUTPUT-MANIFEST.json` binds its exports; the packet
manifest also binds source, test and licensed inputs. Preparation records retain
the corrected duplicate reporting-key and denominator-name findings; the old
prototype evidence was preserved. Final component validation is recorded in
`FOCUSED-VALIDATION.json`, with the exact-head aggregate reported separately.

## Prior work and limits

- #981/#1022/#1043/#1048 establish earlier selected boundary/conditional-memory
  or cross-release facts. This adds licensed-source compilation evidence and
  imports none of those unmerged analyzers or their Rust implementations.
- #373's gap census, #37's FDE-based drift and #875's ISA census remain credited
  context. Their held files, global counts and unresolved interpretations are
  unchanged; no dependency or CPU-dispatch gate is claimed.
- A separate retained ten-byte leaf returning 10506 was only a version lead.
  This packet does not label that leaf as a version API or use it to resolve
  the original dependency version. The assembly has no version constant.

The comparison denominator is 2,418 selected code bytes per image per build,
with eight A/B pair checks across two positive builds and two targets. It is
not a function census, whole-image comparison, Rust implementation or all-input
behavior proof. Caller reachability, table/state construction, runtime CPU
support and original ABI/source identity remain unqualified. No component,
catalogue or progress gate changes.

The next useful question is independently binding the surrounding caller/table
and version evidence in each captured release. The compatible source recipe
and active-input ambiguity alone do not establish that historical context.
