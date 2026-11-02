# RE-009: staking-link state serialization and reader failures

This packet identifies the named `user_to_staking_link2` writer and its matching reader, including the three nonempty row variants and the duplicate-key path, so an independent reconstruction can choose the correct container layout and rejection behavior.

- Component ID: RE-009, storage and state roots.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference tree was used only to select a question, not as implementation source.
- Claim status: observations are fixed ELF bytes, relocations, selected calls and FDE ranges; wire names and control-flow meanings are inferences where stated. Runtime behavior remains unexecuted.
- Scope included and excluded: the selected named field, one tree collector, pair writer and reader, three enum arms, address-formatting call sites, and selected success/error branches. Full snapshot framing, other state fields, persistence and restore entry points, full helper behavior, a complete CFG and a computed root are excluded.

## Reproduce

From the repository root, with Python 3.12.3 on Linux x86-64 and the shared `tools/elf_index.py` and `tools/fde_extents.py` present:

```sh
python3 tools/staking_link_wire94.py --out research/work-items/RE-009-staking-link-wire-94
python3 -m unittest tests.test_staking_link_wire94
(cd research/work-items/RE-009-staking-link-wire-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_link_wire94.py --out work/staking-link-check-a
PYTHONHASHSEED=987 TZ=Pacific/Honolulu python3 tools/staking_link_wire94.py --out work/staking-link-check-b
diff -r work/staking-link-check-a work/staking-link-check-b
```

The generator reads the ELF and writes only `evidence.json` and `variants.tsv`; it checks the input SHA-256 before parsing and never runs the target or an external program. It uses the shared section and CIE/FDE readers, excluding `SHT_NOBITS` from file-backed VA reads. Direct calls, branches, RIP-relative references, and selected instructions are matched as fixed bytes; dynamic relocations and symbols are read with `struct`. Other than the two outputs, the commands above create the two requested comparison directories. Evidence output SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `evidence.json` | `77b5839f1a3007a39221152dcc3fea053b1bb96d882dc5f3a9ec80706406805d` |
| `variants.tsv` | `ae4b81c5df88ba1e0a01253d240fd75787650ac9f961c301c9020fb87042d444` |
| `tools/staking_link_wire94.py` | `c5eb1eb9fd1fcf2c131254de65ad302b28dcdcb1f47bb4136ce056d2f7d73a20` |
| `tests/test_staking_link_wire94.py` | `fdbcdec612a2498fa793bd40f8d062dbf685354ddc8b5e0853538fd3b2df6340` |

## Evidence

Addresses below are linked ELF virtual addresses, not file offsets or rebased runtime addresses. `evidence.json` retains the actual bytes, direct and indirect call sites, referenced literals, conditional destinations, selected FDE endpoints and body hashes. The 21 selected FDE ranges are unwind-described ranges, not proof of complete function boundaries. Analysis is restricted to the recorded paths.

### Writer and tree

`0x231a8c0` selects the one-field outer container header from serializer byte `+0xb`. When that byte is 1 it writes the 21-byte field name at `0x3e0b6a`; when it is 0 it uses the one-element sequence header and omits the name. Values of this mode byte other than 0 or 1 are not characterized as valid configurations. It calls `0x25eadf0`, which calls collector `0x25686b0`, then pair-list writer `0x1e231b0`.

The collector forms two pointers per item: key at node `+8 + 20*i`, value at node `+0xe8 + 21*i`. It uses the node count at `+0xe6`, parent index at `+0xe4`, and child pointers based at `+0x1d0`. The pair array has stride 16. The iterator starts from the root and height, descends through first-child pointers, emits the node key and value at its current index, advances within a node or ascends using the parent index, and prepares the leftmost descendant of the next child before resuming. The count-to-allocation check shifts by 4, tests the high bits, and rejects a shifted size above 9223372036854775800; the largest count passing this arithmetic check is 576460752303423487. Passing the check does not establish allocation success.

`0x1e231b0` writes an array of collected pairs. For each pair `0x1df2010` writes two elements: key first and variant second. Its compact pair marker is byte `92`. The key writer `0x1e0d0a0` and payload writer `0x1e13ab0` pass a 20-byte input and a 42-byte buffer to the same indirect slot `0x5773120`, then pass the result to the string writer. The ELF RELATIVE relocation resolves that slot to `0x29ed380`. The previously researched prefixed-hex helper and its digit table are documented in `research/work-items/bridge-l1-hash-votes-94/README.md`; this packet does not re-analyze that helper. Under that prior interpretation, these are full-width, lower-case prefixed address strings. The exact address parser grammar is outside this packet.

`0x2319930` reads the row's first byte, advances its pointer by one for the address payload, and writes a single-entry variant map. For mode 1 its payload is a one-field named map; for mode 0 it is a one-element sequence. The buffered alternate is called at `0x1df22f6` and retained as a selected FDE, but its full internal branches are not audited here. The direct writer's observed arm mapping is:

| Row tag | Variant text | Named payload field | Reader payload FDE |
| --- | --- | --- | --- |
| 0 | `Requested` | `staking_user` | `0x180f8d0` |
| 1 | `TradingUser` | `staking_user` | `0x175d550` |
| 2 | `StakingUser` | `trading_user` | `0x17950b0` |

The writer mechanically routes any byte other than 0 or 1 to its last arm. That does not establish that other values are valid enum discriminants. The table's text and tags are independently extracted from the reader's character comparisons and success stores, then checked against the writer's referenced strings.

### Reader and failure routes

`0x1866ac0` compares the outer field length and two overlapping blocks of literal bytes. On an already-seen recognized field, its branch at `0x1867593` reaches the duplicate-field diagnostic. On a first recognized field it calls `0x187a310`; an unrecognized name is handed to a separate helper. After a successfully parsed outer map with no recognized field, the selected default path supplies an empty tree. The outer sequence path handles zero or one field, with a separate wrong-length path for larger counts. These statements are conditional on earlier parsing and helper success.

The collection reader distinguishes a map path, `0x264d420`, from a sequence-of-pairs path, `0x2689420`. On the latter path, pair reader `0x174cbd0` reads a 20-byte key, then the variant; after both succeed it checks that the pair count is exactly 2. The variant reader `0x1686820` checks for a one-entry variant map, calls the name reader and dispatches to the three payload readers. Each payload reader has separate map and sequence paths. Its map path compares the appropriate 12-byte field name, reports the corresponding duplicate or missing field through referenced diagnostic templates, and passes a 20-byte destination to the address reader. Its sequence path requires one element; empty and longer sequences have separate error paths. These are selected branches, not a complete corruption grammar.

Both collection paths call `0x2860dc0`. The ELF `GLOB_DAT` relocation for its comparison slot names `memcmp`; the call supplies 20 as the comparison size. For an equal key, the helper copies out the old 21-byte row and writes the new row into the temporary tree. On a new key, the selected insertion path returns marker 3. Both collection callers continue on marker 3; otherwise they construct `duplicate key` and follow error cleanup. Thus, for valid old row tags 0, 1 or 2, a repeated key reaches an error **after** temporary replacement. This does not imply that a partially decoded tree is returned to a caller.

### Inferences and relation to prior work

The collector's key/value arithmetic agrees with the independently documented 20-byte key and 21-byte tagged row in `research/work-items/fees-staking-link-94/README.md`. The selected traversal is an in-order B-tree walk. Under standard `memcmp` semantics, the 20-byte comparator implies ascending unsigned byte order when the tree obeys its ordering invariant; the invariant is not proved for corrupted trees or unaudited insertion helpers. The container helper names in this record follow their previously pinned MessagePack-shaped marker behavior in `research/work-items/RE-009-evm-state-wire-94/README.md`. In named mode the resulting logical shape is a field holding an array of `[address, variant]` pairs; unnamed mode changes the outer and payload struct containers to sequences.

The prior app-hash builder packet records state captures but does not establish this packet's complete snapshot envelope or byte-for-byte root preimage. This packet does not assign the selected writer to a specific persistence entry point or app-hash closure. No snapshot version, hash digest or independently captured nonempty fixture is inferred from the field name alone.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo build scope, compiler/linker flags, two-build comparison, byte masks, target fixture comparison and complete relocation/helper closure: not yet implemented/measured. This packet supplies static expectations and corruption controls only; it contains no self-derived target execution result.

## Results and limitations

The retained evidence covers 21 selected FDEs, 79 fixed instruction windows, 53 direct calls, 29 selected conditional edges, 27 literal references, 3 indirect calls and 3 variant-name rows. These are counts of selected records, not denominators for all reachable functions or branches. The focused suite has 21 tests, including all 31 single-character classifier mutations, wrong digests, altered instructions and branch targets, unmapped and NOBITS addresses, duplicate diagnostic corruption, and arithmetic boundary cases. No progress gate is requested.

The formatter implementation, full outer snapshot entry points, other reader marker forms, allocation failures, malformed trees and ordering under such trees remain outside the checked paths. Next question: which snapshot and app-hash call sites pass this exact named field, and what complete preimage is produced for a nonempty tree?
