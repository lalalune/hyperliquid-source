# staking: epoch snapshot clone, map update and pruning in node 94

This packet establishes how node 94 makes independent validator and delegation snapshots, inserts or replaces them in the epoch map, and repairs that map when old snapshots are pruned, allowing a reconstruction to preserve snapshot ownership and the observed split, merge and retention rules.

- Component ID: staking, validator lifecycle and epoch transitions.
- Target release and full SHA-256: Linux x86-64 node 94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference is a lead only; no reference code is copied.
- Claim status: observed bytes and FDE records, plus bounded interpretation of those bytes. Field and function names and the connection to the larger epoch transition are inferences from existing binary-backed work. Unresolved behavior is listed below.
- Scope included and excluded: nine selected FDE ranges for the two snapshot clones, epoch-map update and split, cursor removal and repair, two borrow helpers, and the snapshot-tree iterator. Three call-site windows and four guard pins in the previously studied epoch-advance caller are context only; its whole function is not claimed. Calendar arithmetic, validator signatures, the nested-value destructor, allocator internals, unwinding and node 115 are excluded.

## Reproduce

From the repository root, using Python 3 and the standard library, with the authenticated target present:

```sh
python3 tools/artifacts.py verify
python3 tools/staking_epoch_snapshot94.py --out research/work-items/staking-epoch-snapshot-tree-94
python3 -m unittest tests.test_staking_epoch_snapshot94
(cd research/work-items/staking-epoch-snapshot-tree-94 && sha256sum -c MANIFEST.sha256)
```

For a separate byte comparison, replace the placeholders with two distinct writable relative directories:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_epoch_snapshot94.py --out <tmp-dir-1>
PYTHONHASHSEED=809 TZ=Pacific/Honolulu python3 tools/staking_epoch_snapshot94.py --out <tmp-dir-2>
diff -r <tmp-dir-1> <tmp-dir-2>
```

The run used Python 3.12.3 on Linux x86-64. GNU objdump 2.42 was used only for manual, focused inspection; the generator and tests never invoke it or another external program. The generator first checks the full artifact digest, imports the repository's ELF and FDE readers, refuses NOBITS mappings, and reads code, relocation records and fixed witnesses from the file. It emits every TSV and `summary.json`; `MANIFEST.sha256` additionally covers this README. The opcode-length recognizer is adapted from `tools/staking_validator_vote_prune94.py`; the bounded instruction interpreter is adapted from the MIT-licensed validator-state insertion draft #1715, itself adapted from `tools/staking_stake_accounting.py`. Neither launches the binary. Independent expected ordered maps and structural checks validate the interpreted fixtures.

## Evidence

All addresses are linked ELF virtual addresses. Ends below are exclusive unwind-described FDE ends, not a claim that unwind metadata finds every function. File offsets and unmasked body hashes are in `functions.tsv`; byte rows, branch targets, decoded calls and relocations are in `instructions.tsv`, `branches.tsv` and `transfers.tsv`. The selected linear decode is complete over these nine FDEs; its two restricted decoders agree on all instruction boundaries. The saved evidence concerns only these selected windows; exploratory disassembly is not used to generate any evidence table. No operand normalization is used.

| Selected role | Start | FDE end |
| --- | --- | --- |
| validator tree clone | `0x33e71c0` | `0x33e7836` |
| nested delegation tree clone | `0x33ed230` | `0x33ed602` |
| epoch-map replace or insert | `0x33a7690` | `0x33a78a7` |
| epoch-map insertion and cascading split | `0x2f91900` | `0x2f926ee` |
| remove at cursor | `0x2fd8bc0` | `0x2fd8e9a` |
| remove leaf and repair | `0x2fc6430` | `0x2fc6fbd` |
| consume snapshot-tree iterator | `0x33b64d0` | `0x33b6891` |
| borrow from left | `0x2fa3300` | `0x2fa3647` |
| borrow from right | `0x2fa7e00` | `0x2fa81ce` |

`incoming.tsv` derives the caller's three direct transfers from their signed displacements: `0x3369889` to the outer clone, `0x3369906` to the epoch-map update, and `0x3369bad` to removal. The existing `staking-force-increase-epoch-94` packet establishes the surrounding epoch transition; its caller is not reanalysed as a selected function here. The clone calls itself and the nested clone, and the map update calls the insertion routine. Removal calls leaf repair, which calls the two borrow helpers. `pins.tsv` retains fixed instruction bytes for these links and the critical layout and branch decisions.

### Snapshot copies

The outer tree stores 32-byte keys and 64-byte values. A value contains a three-word nested-map descriptor and two 20-byte fields. In the observed code the outer node has parent pointer at `+0x420`, parent edge at `+0x428`, u16 count at `+0x42a`, keys from `+0x2c0`, and children from `+0x430`. Outer leaf and inner allocations are `0x430` and `0x490` bytes.

The nested tree has 20-byte keys from `+0x60`, u64 values from `+8`, parent pointer at `+0`, edge at `+0x13c`, u16 count at `+0x13e`, and children from `+0x140`. Its leaf and inner allocations are `0x140` and `0x1a0` bytes. Both clones use capacity 11, recurse on children and restore parent pointers and edge indices. When the nested length is zero the nested root is not cloned; a nonzero length with a null nested root reaches the failure boundary. The seven clone fixtures cover empty and full leaves and height-one outer and nested trees. Each walks both results, checks every row and parent link, and requires the source and output node sets to be disjoint.

### Epoch-map update

The epoch map has u64 keys from node `+8`, opaque 40-byte values from `+0x60`, a u16 node count at `+0x21a`, parent edge at `+0x218`, and child pointers from `+0x220`. Leaf and inner nodes occupy `0x220` and `0x280` bytes. A matching key replaces the complete 40-byte value and returns its old value; inserting a new key increments the map length and marks the returned value absent through the word at result `+0x18`. The unsigned-key fixtures include zero, both sides of the sign bit, and the maximum u64.

On a full 11-key leaf, the selected split uses an old key as the promoted separator. For insertion position `i` among the old keys:

| Position `i` | Promoted old key index | Final left / right counts |
| --- | --- | --- |
| 0 through 4 | 4 | 5 / 6 |
| 5 | 5 | 6 / 5 |
| 6 | 5 | 5 / 6 |
| 7 through 11 | 6 | 6 / 5 |

The new key stays in a child. The 144 deep-split fixtures independently vary all 12 child positions and 12 leaf positions under a full parent; all preserve sorted keys, opaque values, counts and parent links and produce a height-two tree. These are synthetic trees, not a claim about live state.

### Removal, retention and disposal boundary

A cursor can name a leaf entry or an internal entry. For the latter, the remover uses a predecessor leaf and returns the original removed key and value. Leaf repair starts when the remaining non-root count is at most four. A zero parent edge chooses the right sibling; otherwise it chooses the left. In the tested valid trees, old leaf count plus sibling count below 12 merges; 12 or more borrows. A merge can propagate to the parent. The 40 two-level controls cover both parent sides and sibling counts 5, 6, 7 and 11; the caller's root-promotion step is projected after the returned collapse flag. The iterator yields ordered validator rows and releases outer nodes through a checked free hook. The actual per-value destructor is outside this packet.

The caller context pins a prune threshold of 1,000 and a stop when the smallest key is at or above `active_epoch`. In four composed fixtures, 1,001 existing epochs are populated using the interpreted insertion functions, the current validator tree is cloned and installed, and the interpreted removal and iterator are used under a separately projected caller loop:

| Active epoch | Update | Removed keys | Final length | Old validator rows iterated |
| --- | --- | --- | --- | --- |
| 1 | insert 1002 | none | 1002 | 0 |
| 2 | insert 1002 | 1 | 1001 | 1 |
| 1003 | insert 1002 | 1, 2 | 1000 | 1 |
| 1 | replace 1 | none | 1001 | 1 |

Thus the threshold alone does not force the map down to 1,000 when the active boundary prevents removal. The projected loop is not execution of the existing caller. The current snapshot's complete nested tree is checked again after the update; the old fixture's validator row has no nested map, so its external value destructor is not exercised.

### Failures and controls

Six injected cases reach recorded failure call sites for outer clone allocation, nested clone allocation, nonempty nested map with null root, empty map allocation, split leaf allocation and split root allocation. The hook stops at the boundary; cleanup and unwinding are not simulated. Five individual private byte mutations change a clone branch, split threshold or pivot, capacity, or underflow threshold. Each is detected by a fixture content or structural assertion; none is credited merely for an out-of-model access. Digest, file-backed range, NOBITS, fixed-byte pin, malformed fixture and truncated/unsupported opcode controls are in the unit tests.

## Implementation and comparison

Rust implementation: **not yet implemented**. There is no Cargo build, compiler or linker claim, byte-equivalence comparison, normalization mask, dynamic execution of the captured node, or whole-ELF comparison. The only comparison is between the limited instruction interpreter and independently constructed synthetic tree expectations. Allocations, byte copies and deallocations use bounded hooks; failures stop at their modeled boundary. The synthetic pointers, payloads and epochs are fixtures, not captured chain state. There are no keys, network actions or target processes.

## Results and limitations

- Nine FDE windows cover 13,194 file bytes and 2,744 decoded instruction starts. The normal synthetic fixtures reach 2,092 of those starts; 56 of 188 conditional branches have both outcomes observed. This denominator applies only to the selected windows and fixtures.
- The generator checks 1,249 normal cases: 7 clones, 144 insertion/replacement, 7 unsigned-key boundaries, 144 two-level insertion splits, 850 leaf removals, 49 internal removals, 40 two-level removal repairs, 4 iterators and 4 composed lifecycles. It also checks 6 injected failure boundaries and 5 detected code mutations. The focused unit suite has 18 passing tests and no skips.
- Selected FDE bounds, reached instruction addresses and branch outcomes are not a complete CFG, proof of all valid states or component coverage. Deep clone fixtures stop at height one; insertion and removal exercise taller selected cases but do not prove arbitrary-height behavior. The pre-existing epoch-advance caller is represented only by fixed context pins and a projected loop.
- External allocation behavior, cleanup on real allocation failure, nested-value destruction, panic unwinding, live epoch retention settings and target runtime behavior remain unproved. No progress gate is requested.

Next question: trace destruction of replaced or pruned snapshots with nonempty nested delegation maps, including allocation-failure unwinding, without assuming the iterator releases those nested values.
