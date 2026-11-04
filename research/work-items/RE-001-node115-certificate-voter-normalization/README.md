# RE-001: node #115 certificate voter-map normalization

- Component: QC/TC decoding and voter-map representation; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Eight complete FDEs / 4,084 bytes, with exclusive ELF VA ends in `records.json`. No full component gate changes.

## Finding

Certificate voter vectors are not used unchanged as maps. The QC reader `0x5968d20` calls `0x4de6470`; the TC reader `0x5968f10` decodes rows with callback `0x5820c70` and calls `0x4dbf950`. The QC map reader uses vector callback `0x5820e50`. Both normalize successfully decoded rows before selecting their map representation.

| Policy | QC | TC |
| --- | --- | --- |
| Decoded row stride | 96 bytes | 104 bytes |
| Key | First 20 bytes (signer) | First 20 bytes (signer) |
| Short sort | `0x53e6aa0` | `0x53ea3d0` |
| Adjacent-run compactor | `0x5b2d7c0` | `0x5b2e330` |
| Flat constructor | `0x5801ca0` | `0x5808d90` |
| Tree constructor | `0x515d480` | `0x5164930` |

At input lengths 0 and 1, sorting is skipped. Lengths 2 through 20 use insertion sorting by unsigned lexicographic comparison of exactly 20 bytes (`memcmp`, bound through its relocation). Equal keys do not move ahead of each other: both the initial comparison and the insertion scan move a row only on a strict negative comparison. These paths therefore preserve input order among equal signers.

Length 21 or greater calls a different sorting implementation (`0x4f39140` for QC, `0x4f3ada0` for TC). That call boundary is authenticated, but its ordering and stability are not claimed here. No conclusion about which *wire-order* duplicate wins is made for that route.

After sorting, both compactors compare the first 16 plus next 4 bytes. Differing payload, signature, round or padding bytes do not distinguish keys. The first duplicate swaps the entire later row into the previous retained slot. Later duplicates likewise replace that slot by a full-row swap; distinct keys are copied forward into the kept prefix. The logical vector length is updated after compaction. Thus each adjacent equal-key run retains its last whole row in the order supplied to the compactor. Tail bytes are not part of the resulting map and are not promised to be zeroed.

For input vectors shorter than 21, stable sorting plus this replacement means **the last decoded occurrence of a signer supplies the retained value**. For example, `(B, first), (A, middle), (B, last)` becomes `(A, middle), (B, last)`. This is a deserialization normalization rule, not a statement that either signature is cryptographically valid.

The representation threshold is evaluated **after** compaction. At most 64 surviving rows use the flat constructor, including exactly 64; 65 or more use the tree constructor. Consequently, 65 post-sort rows with one repeated signer become 64 rows and select flat storage. The original encoded vector length does not determine that choice. Generic constructors remain boundaries; their internal balancing, allocation and failure behavior are not reconstructed.

## Validation and limits

Operand-derived relations compare the short insertion/compaction path against an independent sorted last-value dictionary. Exhaustive small sequences and deterministic cases through length20 distinguish key ordering, duplicate payload selection and stable ties. Separate post-sort inputs exercise adjacent-run compaction without assuming long-sort stability. Unique counts0..129 with repeated rows exercise the representation boundary. Four actual native operand mutations distinguish the inclusive64 threshold, the twentieth key byte, stable equal-key handling and duplicate branch polarity.

The complete bodies and incoming call sites bind this behavior to certificate decoding. Wire primitives, malformed-vector cursor behavior, signature decoding/verification, quorum rules, the long-sort implementation and complete certificate acceptance remain outside the claim. The two analogous QC/TC paths are one policy contribution; generic clone bodies are not counted as separate discoveries. No captured binary is executed or emulated.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-certificate-voter-normalization/export_disassembly.py
python3 research/work-items/RE-001-node115-certificate-voter-normalization/verify.py --controls
python3 research/work-items/RE-001-node115-certificate-voter-normalization/relations.py
python3 -m unittest discover -s tests -p 'test_node115_certificate_voter_normalization.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-certificate-voter-normalization/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

[PR #2525](https://github.com/lalalune/hyperliquid-source/pull/2525) already establishes last-row adjacent-key compaction for a different node115 32-byte-row execution-state container. [#1844](https://github.com/lalalune/hyperliquid-source/pull/1844) covers older-release stable sorting of 32-byte vote snapshot rows. [PR #1859](https://github.com/lalalune/hyperliquid-source/pull/1859) also establishes the older outcome-settlement 2–20 stable-sort and last-duplicate rule, with long-sort stability unresolved. Those generic rules are credited antecedents. The addition here is their bounded, target-specific consequence for QC/TC decoded voter vectors and the post-compaction flat/tree selection.

[#1444](https://github.com/lalalune/hyperliquid-source/pull/1444), [#1467](https://github.com/lalalune/hyperliquid-source/pull/1467) and [#1391](https://github.com/lalalune/hyperliquid-source/pull/1391) cover earlier certificate/signing preimages; [#999](https://github.com/lalalune/hyperliquid-source/pull/999) covers proof validation. This packet does not replace or re-claim their wire/cryptographic work.

GPT-6.1 Terra searched all-state PR metadata and available file evidence. The retained audit states historical-content and patch availability limits; an absolute uniqueness guarantee is not possible for inaccessible content. Independently authored MIT analysis and relations reuse existing MIT evidence/export scaffolding. No unlicensed inferred source is copied. Full source equivalence and hosted CI are not claimed.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
