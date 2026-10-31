# RE-014: two selected no-FDE code correspondences, node #94 to #115

- Component: release drift, bounded follow-up to RE-001.
- Node #94: 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Node #115: 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Maintained source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Status: observed fixed-artifact static correspondence, with the limits below.
- No reconstruction/component gate, Rust implementation or whole-release count.

## Question and scope

Do the two previously bounded #94 code candidates have complete, unique
byte/operand/local-CFG counterparts in the captured #115 artifact? Diagnostic
path disappearance, FDE membership and similar instruction prefixes are not
substitutes for comparing their complete bytes.

| Candidate | Node #94 linked VA interval | Node #115 linked VA interval | Byte pairs | Instruction pairs |
| --- | --- | --- | ---: | ---: |
| A | `[0x5631580,0x56319fd)` | `[0x62e4700,0x62e4b7d)` | 1,149 | 285 |
| B | `[0x56319fd,0x5631ef2)` | `[0x62e4b7d,0x62e5072)` | 1,269 | 324 |

Both mappings have linked-address delta `0xcb3180`. The complete selected
bodies occur exactly once each in the entire authenticated #115 file. Every
raw code byte compares equal; there are **no byte masks**. Each candidate has
nine local block leaders, six direct local branches and all rows reachable
from the selected first instruction. There are no CALL or RIP/EIP-relative
operands within either selected body.

The denominator is 2,418 code-byte pairs / 609 instruction pairs / 12 local
branch pairs. There are 4,836 raw code bytes / 1,218 native instruction records
across the two images; these are not additional function or reconstruction
counts. File offsets, section coordinates and PT_LOAD coordinates are separate
fields in `REPORT.json` and must agree uniquely.

## Prior work and exclusions

- [#373](https://github.com/lalalune/hyperliquid-source/pull/373), head
  `4190e47bcb7a4c6c019c31b27f857078276cb5d4`, already reports both containing
  2,493-byte gaps and raw E8 census. Those gap counts are credited context,
  not this packet's new result. Its held decoder/packet is unchanged.
- [#37](https://github.com/lalalune/hyperliquid-source/pull/37), head
  `7752b55f06946cc86a9ba4bde7c8acb24c083715`, compares FDE-described code and
  explicitly excludes code without FDEs. This packet does not repeat its
  whole-image classifications or edit its held paths.
- [#875](https://github.com/lalalune/hyperliquid-source/pull/875), head
  `07f43c689bd1e24de4f605c297e9faa8dbb8f1f3`, studies an FDE-bounded ISA census.
  Neither that decoder nor its gate/CPU-dispatch interpretations are used.
- [#981](https://github.com/lalalune/hyperliquid-source/pull/981) bounds the
  #94 candidates; [#1022](https://github.com/lalalune/hyperliquid-source/pull/1022)
  and [#1043](https://github.com/lalalune/hyperliquid-source/pull/1043) study
  their distinct conditional #94 memory contracts. This independently reads
  both maintained captures, imports none of those unmerged analyzers and does
  not restate their contracts as new #115 behavioral measurements.

## Reproduce

Recorded host: Linux x86-64, Python 3.12.14, GNU objdump 2.44. From the repository
root with existing pinned LFS artifacts and seven genuine source submodules:

```sh
mkdir -p /tmp/hlgap work
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/hlgap python3 -B \
  tools/gap_candidate_release_mapping.py --output-dir work/gap-release-fresh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/hlgap python3 -B -m unittest discover \
  -s tests -p test_gap_candidate_release_mapping.py -v
make --jobs=1 'PYTHON=python3 -B' doctor verify test catalogue-check reproduce
```

Use a new output directory; existing evidence is refused and preserved. GNU
objdump is required explicitly; missing/non-GNU tools do not count as success.
No package installation, captured executable/emulator, network, chain, signing
or paid dataset action is performed by the producer.

## Evidence and comparison

`REPORT.json` records both full input identities, selected coordinates,
independent raw FDE/CIE neighbors and source/helper hashes. `instructions.json`
retains all native rows and the comparison records. Four `.objdump` files are
the original tiny-view native exports. `OUTPUT-MANIFEST.json` binds those six
exports; `MANIFEST.json` binds the complete packet plus source/tests.

The producer authenticates one **immutable Python bytes object per target**.
All section/PT_LOAD/unwind/search/slice facts derive from those same objects;
GNU receives only the selected 1,149- or 1,269-byte private views. It never
opens an original capture pathname. This is not a claim of an atomic filesystem
read or stable source pathname: the admitted immutable bytes themselves must
have the complete expected digest. Later source changes cannot change them.

Every GNU row's address, width and encoding must cover the admitted slice
exactly. Direct branch destinations are independently recomputed from their
actual signed rel8/rel32 encodings; the displayed linked address must agree
before it becomes a candidate-relative comparison coordinate. All other
mnemonic/scalar/memory operands remain exact. The raw encodings never change.

The twelve focused tests include one-sided actual #115 scalar/memory/branch
byte changes, complete-body duplication/missing matches, conflicting section
or PT_LOAD mappings, malformed actual unwind records, a misaligned encoded
branch, wrong/stale native views, a wrong rendered branch destination and an
unpermitted nonbranch operand change. Real private source-file mutation tests
the same admission helper; replacing a private source alias during production
must preserve all admitted metadata/native outputs. Actual CLI reruns reproduce
all seven outputs and preserve existing evidence; wrong input fails before
output creation. Original captures are never modified or copied to fixture
files. `FOCUSED-VALIDATION.json` binds the commands and normal/optimized logs.

`PREPARATION-FAILURE.json` preserves the author's first prototype refusal: GNU
prints raw branch addresses with `0x`, whereas the first parser required bare
hex. Optional display-prefix acceptance was corrected before freeze; signed
destination verification and every other comparison remain strict.

## Results, limits and next question

Both selected #115 bodies intersect zero of the 135,313 parsed raw FDE records
(#94 parse: 121,299 records). Those are metadata parse-completeness counts,
not function counts. The closest following FDE-sized regions are **408 bytes
in #94 versus 2,914 in #115**. Their raw FDE records differ, and that wider
region is explicitly excluded rather than transferred by the shared delta.

This is complete only for the two selected code intervals and their local
static correspondence. It establishes no original function/source/type/ABI
identity, caller or dispatch closure, runtime table/state/allocation identity,
CPU feature availability, whole-call termination, arbitrary-state safety,
Rust implementation, whole-release behavior or binary equivalence. No unseen
or semantically equivalent alternative implementation census is claimed.
No unlicensed inferred reference implementation was read or copied.

The next useful question is whether independently established callers in each
release supply the same required table/region/CPU conditions. Exact body
correspondence alone does not establish those conditions.
