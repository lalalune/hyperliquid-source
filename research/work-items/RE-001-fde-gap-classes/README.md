# RE-001: node #115 gaps outside unwind ranges

The authenticated node #115 capture contains 133 same-section `.text` gaps
with bytes other than `int3`. This packet classifies their bytes and checks
selected references into them. Seven islands have 16 validated entrypoints;
a separate 334-byte island has only data-pointer references in this scan.
An island is not a validated function or an ownership assignment.

- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Component/task: RE-001 function-map work; component ownership unassigned.
- Migration input: PR #40 head `4536d01b4a9de66d5c54d5a0a956f617246576e4`.
- Current source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Observation: gap bytes, disassembly, relocation records and the references
  revalidated from containing FDE starts.
- Inference: an entered island may contain code without unwind information.
- Unresolved: boundaries within islands, source/library identity, register
  indirect targets, jump tables, CFG reachability and whole-node coverage.

## Reproduce

From the repository root, Python 3.13.2 and GNU objdump 2.47.20260726:

```sh
make PYTHON=/opt/miniconda3/bin/python3 fde-gaps
python3 -m unittest discover -s tests -p test_fde_gap_classes.py -v
python3 tools/verify_packets.py
```

`fde-gaps` accepts only the active #115 target. It authenticates the artifact
against the repository manifest before static decoding. No captured executable
is run. The migration was regenerated twice on macOS arm64 using native GNU
binutils against the Linux x86-64 bytes. Both TSV exports match the original
#115 records byte for byte. The JSON comparison changes only the recorded GNU
provider version. The second regeneration must match all three current files.
The older target's CLI option, Makefile invocation and active outputs were
removed; the original PR remains a Git parent and preserves that history.

## Method and evidence

The shared parser obtains actual `.eh_frame` extents and the same-section
gaps between them. Each non-int3 gap is disassembled from its start with
15 bytes of lookahead so an instruction cut by the gap end is detected.
A separate canonical-NOP byte matcher checks the leading fill classification.
The remaining ranges are split at int3 runs with fill trimmed at both ends.

The tool streams the complete `.text` disassembly for direct branches and
RIP-relative operands, reads RELATIVE/IRELATIVE relocation addends, and records
reads of the relevant relocation slots. Every code source is disassembled
again from its containing FDE start and must match the same instruction at
the same address. Only an FDE-covered source or relocation slot can establish
an entry, and the destination must be an instruction start. Pointer entries
also require an `endbr64` destination. Island-originated references cannot
establish an entry because data may decode as instructions.

| Classification | Count | Bytes |
| --- | ---: | ---: |
| Fill-only gaps | 128 | 2,057 |
| Zero-byte gap | 1 | 6 |
| Gaps with other non-fill bytes | 4 | 63,886 |

The nine trimmed islands comprise seven entered islands, one pointer-only
island, and one four-byte zero island. Their exact bounds, raw-byte SHA-256
values and entrypoint lists are in `node-115-gap-classes.json`. The zero island
is part of the six-byte gap; the remaining two bytes are fill. There are no
byte-matcher disagreements or gap ends inside decoded instructions in this
capture. `node-115-gap-xrefs.tsv` retains the bounded reference records.
Raw GNU output for all nine island intervals is under `raw/`; nearest-symbol
annotations are not source symbols and data decodes do not prove code.

## Validation and limits

Fifteen focused tests cover fill parsing, malformed/wrapped decode rejection,
source revalidation, mid-instruction destinations, data pointers, relocations,
NOBITS overlap and refusal of the retired target. Eighteen shared FDE parser
tests also passed. `migration-validation.json` records hashes, commands, the
provider comparison, repeat generation and repository-check outcomes.

The new worktree's artifact SHA-256 and signatures verified, but `make verify`
stopped because its upstream submodules were not initialized. Final integration
must run the repository checks with the existing pinned imports; this is not
claimed as a full `make verify` pass in the isolated worktree.

Independent Rust reconstruction and binary comparison: not implemented here.
No gates or reconstructed-byte registry entries change. These results do not
establish complete functions, ownership, behavioral equivalence or a whole-node
denominator. Next question: trace the #115 CPU-feature selection of the
relocation-backed entrypoints and determine bounded code/data ownership.

## Source providers for the gap islands

At base `2da45cb0a761cff6b478e40421699857d87a94df`, the catalogue divided all
18,328 compared windows by the 135,313 indexed starts. The numerator included
13 assembly windows outside every FDE. Matching the authenticated addresses
gives 18,315/135,313 (13.53528%). At this revision, all 18,315 also have the same
end as an actual FDE. The catalogue metric measures starting addresses, so a
future compared prefix can start at an indexed address without covering the full FDE.

The thirteen other windows span 62,925 bytes and exactly cover five of the
original packet's seven entered islands. Their start addresses match 13 of
the original 16 independently identified entrypoints. Two Zstandard HUF
windows cover one island (2,418 raw-equal bytes). Eleven BLAKE3 windows cover
the four SIMD islands (60,507 compared bytes, equal after the recorded
relocations). The [dependency windows](../RE-002-node115-dependency-windows/README.md)
and [native assembly census](../RE-002-node115-native-libs-wave2-census/README.md)
established those source comparisons. The [new cross-reference](provider-coverage.json)
binds them to this packet's independently measured gap bounds and entrypoints.
The [previous popcount comparison](https://github.com/lalalune/hyperliquid-source/pull/1068)
covers the 98-byte island at `0x63f0960` separately. The [GCC startup helper comparison](https://github.com/lalalune/hyperliquid-source/pull/7421)
reports a compatible 185-byte `crtbeginS.o` region at `0x1419330`. Neither record is
part of the base revision’s aligned-window registry. The four-byte zero island at
`0x5d249c0` has no assigned provider here.

### The 334-byte pointer-only island

Both references previously identified at `0x633a311` and `0x633a3b9`
lead to `0x633a540`. Rebuilding the generic x86-64 generator in two
published `sha3-asm` releases places a local ELF `OBJECT` named `iotas`
at this address when the object is aligned to the four neighboring Keccak
FDEs. Its 24 little-endian 64-bit words independently match the iota round
constants generated by the recurrence in [FIPS 202, section 3.2.5](https://csrc.nist.gov/pubs/fips/202/final).

| Node #115 interval | Bytes | Source observation |
| --- | ---: | --- |
| `0x633a500..0x633a540` | 64 | Eight explicit zero words before the table |
| `0x633a540..0x633a600` | 192 | Complete `iotas` object |
| `0x633a600..0x633a64d` | 77 | NUL-terminated CRYPTOGAMS credit at the end of the source object's `.text` |
| `0x633a64d..0x633a64e` | 1 | Captured `cc` after the source section ends |

Both source builds reproduce the same 333-byte data suffix. Their agreement
establishes compatible source and leaves the crate version unresolved.
The original disassembler's 334-byte island includes the final extra byte.
These data are excluded from the new unwind-start numerator and carry no
additional executable-byte registry credit.

The verifier requires Python 3.10+, Perl, Clang with x86-64 ELF support and
GNU readelf. From the repository root, fetch the two published archives
once and run the comparison offline. Their SHA-256 values are checked against
pinned [Cargo registry records](https://index.crates.io/sh/a3/sha3-asm).
The public generator runs in a temporary directory. The resulting objects
and the captured node are inspected as data.

```sh
archives=$(mktemp -d)
for version in 0.1.6 0.1.9; do
  curl -fsSL "https://static.crates.io/crates/sha3-asm/sha3-asm-$version.crate" \
    -o "$archives/sha3-asm-$version.crate"
done
python3 -B research/work-items/RE-001-fde-gap-classes/compare_providers.py "$archives" --check
make catalogue-check
```

The source archives retain their original CRYPTOGAMS notices. This packet
distributes the verifier and measurements.
