# staking: jailed-signer cursor deletion and right-side tree repair in node #94

Node #94 removes a jailed signer through predecessor replacement, ordered leaf compaction, sibling merge or right-side borrowing, and a returned continuation cursor, allowing the cleanup after a validator profile change to preserve the set and its traversal as the tree shrinks.

- Component ID: `staking` (staking and validator lifecycle).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as an untrusted lead only.
- Claim status: observations are authenticated bytes and selected static-interpreter outcomes; the staking field and operation names are inferences from previously established context. Untested behavior is unresolved as stated below.
- Scope included and excluded: four FDE-described cursor, leaf-repair, merge and right-transfer ranges, with two incoming call instructions as context. The already studied profile-change host, the removal entry, the left-transfer helper, root replacement, allocators and panic/unwind implementations are outside this packet. No component gate is requested.

## Reproduce

From the repository root, with Python 3.12.3 and the authenticated artifact:

```sh
python3 tools/artifacts.py verify
python3 tools/staking_jail_tree_repair94.py --out research/work-items/staking-jail-tree-repair-94
python3 -m unittest tests.test_staking_jail_tree_repair94
python3 tools/catalogue.py --check
(cd research/work-items/staking-jail-tree-repair-94 && sha256sum -c MANIFEST.sha256)
```

For two independent comparisons, choose an empty relative temporary directory:

```sh
TMPDIR=work/staking-jail-repair-verify
mkdir -p "$TMPDIR/a" "$TMPDIR/b"
PYTHONHASHSEED=17 TZ=UTC python3 tools/staking_jail_tree_repair94.py --out "$TMPDIR/a"
PYTHONHASHSEED=811 TZ=Pacific/Honolulu python3 tools/staking_jail_tree_repair94.py --out "$TMPDIR/b"
diff -r "$TMPDIR/a" "$TMPDIR/b"
```

The generator verifies the complete input digest and each selected FDE body hash before interpreting anything. It uses the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; `SHT_NOBITS` is excluded from file-backed reads. It starts no external programs and does not execute the captured node. The decoder and interpreter are adapted from the MIT-licensed `tools/staking_stake_accounting.py`; the synthetic tree-fixture approach is adapted from the related delegation-prune packet #1699. These fixtures and checks use the present key-only node layout and selected bodies. GNU objdump 2.42 was used only for bounded human inspection; generated files and tests do not parse or call it. `MANIFEST.sha256` contains the output and README hashes.

## Evidence

All addresses below are ELF virtual addresses; generated tables also contain file offsets. The half-open ends come from actual `.eh_frame` FDE records, not the next unwind start. An FDE is an unwind extent, not proof of a complete source-level function or of complete function coverage.

| Subject | Start | Exclusive end | Selected role |
| --- | --- | --- | --- |
| Cursor delete | `0x2fd9460` | `0x2fd96eb` | Leaf delete or internal predecessor replacement; return key and continuation |
| Leaf and repair | `0x2fc8680` | `0x2fc8d66` | Compact a leaf and choose or propagate repair |
| Merge | `0x2faebf0` | `0x2faef95` | Merge siblings with their parent separator |
| Right transfer | `0x2fa9270` | `0x2fa955b` | Move entries from the right sibling through the parent |

The earlier profile-jail reconciliation packet #1635 traces the profile-change loop at `0x3995e50` to removal entry `0x33ad2f0`, passing the current jail set at staking state `+0xd8`. The direct call at `0x33ad3e8` reaches the selected cursor deletion function. The two calls are retained as byte-checked linkage witnesses in `anchors.tsv`; neither enclosing body is a subject of this packet. The identification of this set as jailed signers relies on the earlier serializer-backed field mapping. That packet's signer projection, set difference, and profile mutation are not reanalysed here.

The selected key-only nodes have 20-byte entries at `+0x08`, a parent pointer at `+0x00`, a 16-bit parent edge index at `+0xe4`, a 16-bit occupied count at `+0xe6`, and child pointers starting at `+0xe8`. The modeled free boundary receives `0xe8` for a leaf and `0x148` for an internal node. Eleven entries fit in a node. These are node-relative offsets, not staking-state offsets. Parent links and edge indices are checked after each completed synthetic deletion.

### Deletion and continuation

The input cursor carries a node, height and index. At height zero the cursor function calls the leaf body. At positive height it enters the child before the selected separator, follows rightmost child pointers to a leaf and removes its last key. The removed predecessor replaces the selected internal key; the original selected key is returned. The continuation cursor identifies the next in-order key or the end. The checker walks the returned gap and parent links independently. On a single root leaf, deletion shifts the key suffix left and decrements the count; it leaves the unused trailing bytes as they were. The 66 single-leaf cases cover every slot at every occupied count from one through eleven and check the complete leaf byte projection, including its stale tail.

### Repair decisions

The rows describe valid modeled trees. `n` is the leaf count before deletion, and `s` is the selected sibling count. The threshold uses the pre-deletion count.

| Condition | Observed selected path |
| --- | --- |
| Remaining leaf count at least five | Return without sibling repair. |
| Underfull leaf with no parent | Return without a sibling. |
| Underfull leaf with nonzero parent edge | Select its left sibling. |
| Underfull leaf at parent edge zero | Select its right sibling; an empty parent reaches a panic boundary. |
| `n + s < 12` | Merge siblings and the parent separator. |
| `n + s >= 12` | Transfer through the parent from the selected sibling. |
| Parent becomes underfull | Continue repair upwards; fixture cases include internal-level repair and cascading merges. |
| Internal root becomes empty | Write byte 1 through the supplied flag; replacement of that root is the caller's responsibility. |

The selected right-transfer helper is exercised at leaf and internal height with transfer amounts one through five. For the 180 valid direct-transfer fixtures, an independent tree walk checks the entire sorted key sequence, parent separator, child backlinks, occupancies and absence of deallocation. These direct calls establish a helper contract for those fixtures; they do not establish that every transfer amount arises from a staking action.

The left-transfer call at `0x2fc883a` targets `0x2fa5270`, a subject of the open profile-jail reconciliation packet. This packet records and stops at that boundary instead of interpreting its body. Of 1,106 generated deletion scenarios, 1,070 complete and match the independent tree, removed-key, successor, flag and free-count checks; 36 stop at that prior-work boundary and are not counted as matches. The complete set includes root-leaf, two-child, height-two and selected height-three synthetic trees. `cases.tsv` records the inputs and the outcome of every scenario.

`controls.tsv` records four deliberately corrupt descriptors. The merge rejects an index above the selected node count and a merge that would reach twelve occupied entries; the right transfer rejects a destination at or above twelve after transfer and a request larger than its donor. The static interpreter reaches the corresponding captured panic boundary before fixture tree bytes change. It does not implement the target panic routines. `flags.tsv` checks preservation of incoming flag bytes 0, 1, 2 and 255 except for the observed empty-internal-root write of 1; the noncanonical input bytes are corruption controls, not claims about normal runtime flags. Eight single-byte mutation controls change the underflow or merge thresholds, predecessor index, leaf count, and right-transfer guards or donor count. Each unmodified fixture passes before its changed fixture is checked, and each mutation is detected.

`functions.tsv`, `instructions.tsv`, `branches.tsv`, `calls.tsv` and `anchors.tsv` preserve the body digests, linearly decoded instruction bytes, direct branches and call targets, selected byte witnesses and observed reachability. `transfers.tsv`, `cases.tsv`, `controls.tsv`, `flags.tsv`, `mutations.tsv` and `summary.json` contain the reproducible synthetic outcomes. Register-indirect calls and external helper bodies are not a closed call graph.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build scope, lockfile, compiler and linker identity, target differential execution, raw and normalized implementation comparisons, call/data/relocation/vtable closure and whole-ELF comparison are **not yet implemented or measured**. No normalization mask is applied to the recorded target bytes.

The interpreter reads the target's instruction bytes and runs them in synthetic memory. Copy/move, deallocation and panic boundaries are modeled; the allocator, actual panic/unwind behavior and the external left-transfer body are not executed. The target binary itself is never executed.

## Results and limitations

The four selected FDEs contain 4,097 bytes and 866 linearly decoded instruction rows. The completed deletion cases reach 697 rows; including direct right-transfer fixtures reaches 720. Of 68 conditional instructions, both edges occur for 29 in completed deletion cases and for 33 when direct-transfer fixtures are included. These are selected-fixture counts, not component coverage or proof of all control flow. The focused suite passes 16 tests with no skips. Two regenerations with different hash seeds and time zones, with an empty executable search path, are byte-identical. The artifact verification and catalogue checks pass.

The outer search and root promotion, left-transfer behavior, allocation and unwinding, arbitrary tree heights and all validator-action gates are unresolved in this packet. The four corruption controls stop at panic boundaries, not recovered error handlers. The selected ranges do not establish a reconstructed Rust implementation or full staking and epoch-transition coverage; all component progress gates remain open.

Next question: can an independently authored set deletion preserve the returned cursor, root promotion and ownership behavior across all sibling directions without relying on modeled boundaries?
