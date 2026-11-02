# RE-017: post-block retention in three node 94 lanes

This packet establishes how a selected-key list drives post-block markers, map splits and the following checkpoint gate in three lanes, including the distinct cutoff used when an older marker is larger and the saturated maximum-key case.

- Component ID: `abci`, RE-017.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519`; the unlicensed reference lead is `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only to choose questions.
- Claim status: observation for the authenticated byte windows, relative targets, operand values, FDEs and specified branch consequences; ordered-map naming, general multilevel partition semantics and actual reachability are inferences or unresolved.
- Scope included and excluded: 14 selected unwind ranges for the split, count, merge and selected cleanup families, plus previously unreported connecting windows in three earlier block-application ranges. The original state loader, its GOT and call site, upstream key selection, the existing hash builder, and previously studied worker bodies are boundaries. Node #115 and visor are separate targets.

## Reproduce

From the repository root, with Python 3.12 or later and the node #94 artifact present:

```sh
python3 tools/abci_retention94.py --out research/work-items/RE-017-quorum-retention-94
python3 -m unittest tests.test_abci_retention94 -v
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_retention94.py --out work/retention-repro-a
PYTHONHASHSEED=271 TZ=Pacific/Honolulu python3 tools/abci_retention94.py --out work/retention-repro-b
diff -r work/retention-repro-a work/retention-repro-b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-quorum-retention-94 work/retention-repro-a
(cd research/work-items/RE-017-quorum-retention-94 && sha256sum -c MANIFEST.sha256)
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The two `work` directories must initially be empty. Development used CPython 3.12.3 on Linux x86-64. The producer checks the complete target SHA-256 before parsing, uses `tools/elf_index.py` and `tools/fde_extents.py`, rejects non-file-backed or ambiguous section mappings, and decodes only specified instruction forms. GNU objdump 2.42 with `-d -Mintel` was used for bounded human review; neither the producer nor tests invoke it or parse its output. No captured executable, network, key, chain action or user state is used. `MANIFEST.sha256` covers all files in this work item except itself; the producer emits the other evidence files but does not generate this README or the manifest.

## Evidence

All addresses are link-time ELF virtual addresses; tables separately give file offsets. Ends are exclusive. `functions.tsv` retains the original bytes, SHA-256, FDE and CIE identities for each selected range. FDEs are unwind ranges, not proof of source-function boundaries. `windows.tsv` contains selected unmasked bytes, including the connecting instructions in the three already-studied block owners. `branches.tsv`, `calls.tsv`, `failure-jumps.tsv`, `lane-layout.tsv`, `literal-refs.tsv`, `literals.tsv`, `relocations.tsv`, and `lsda.tsv` decode specified bytes rather than a complete disassembly or control-flow graph.

### Existing boundary and newly selected functions

The prior [state-link packet](../RE-017-abci-state-link-94/README.md) ties a state-file path to the Location-bearing loader; [round clock](../staking-round-clock-94/README.md) follows one reload into the local-state host; [app-hash builder](../RE-009-app-hash-builder-94/README.md) records that the three block owners insert a computed value in their first map. An earlier worker handoff identifies a possible route to a block owner, but neither those records nor this packet prove that the exact loader result is the same live object used here. The following are conditional continuations of those boundaries, not a newly claimed loader-to-worker execution.

| Role | Low lane | Shared by primary and secondary lanes |
| --- | --- | --- |
| 32-byte-value split | `0x1b03d00` | `0x4288070` |
| 32-byte-value count | `0x1b02d40` | `0x4287cb0` |
| 32-byte-value merge | `0x1b02980` | `0x4286a50` |
| 56-byte-value split | `0x1b030f0` | `0x428b270` |
| 56-byte-value count | `0x1b02fc0` | `0x4287a40` |
| 56-byte-value merge | `0x1b021c0` | `0x4286680` |
| Selected old 56-byte map cleanup | `0x28a9950` | `0x49ad7a0` |

The low, primary and secondary boundary owners begin at `0x2209d40`, `0x42e4600` and `0x42e5d40`, respectively. Their original calls into the loader and builder are not regenerated as new claims. The two count pairs have identical complete FDE bytes: 313 bytes for the 32-byte-value pair and 293 for the 56-byte-value pair, with no normalization mask. That comparison is between captured byte ranges, not a Rust or whole-node equivalence result.

The separately submitted block-results packet records the secondary owner's earlier update of the 56-byte-value map at receiver `+0x3b10`, with the map address passed through `r12`. The new split call at `0x42e6c34` also takes `r12`; the selected new window checks that map's root and count and later replaces its header. Conditional on the earlier setup and no intervening change to that register or object, the updater's map is the second map subsequently split here. The earlier update instruction and call are prior-work boundaries and are not republished as new evidence. This does not establish execution of either path or loader-result identity.

After the retention paths rejoin, each owner conditionally releases the temporary key vector, compares its marker dword with 2 and, if unequal, calls the corresponding previously studied checkpoint-admission range: `0x220bed0`, `0x42e73d0` or `0x42e7980`. The new connecting instructions and three newly recorded call sites are in the selected windows and call table; the checkpoint bodies themselves are boundaries covered by [snapshot admission](../RE-001-snapshot-admission-94/README.md). A matching dword of 2 bypasses this call. This sequence assumes all intervening selected calls return normally and does not establish the conditions that made the earlier state loader run.

### Marker and cutoff

After the already-selected key vector has been formed, a zero length branches to the independent third-map gate. Otherwise the selected instructions find the unsigned maximum key `M`. Given existing raw marker words `T` and `V`, the pinned compare, `setb`, low-bit test and conditional moves implement:

| Condition | Marker tag written | Marker value written | First two-map cutoff |
| --- | --- | --- | --- |
| `(T & 1) != 0` and `M < V` | `T` | `V` | `min(M + 1, 2^64 - 1)` |
| Otherwise | `1` | `M` | `min(M + 1, 2^64 - 1)` |

For example, conditional input `(M, T, V) = (9, 1, 30)` retains marker value 30 but sends cutoff 10 to the two split calls. This example is a synthetic raw-word control, not a claim that the input state occurs in a running node. At `M = 2^64 - 1` the increment saturates, so the depth-zero partition described below keeps an entry whose key is also `2^64 - 1`.

The low and secondary marker pair is at receiver `+0x3ae8/+0x3af0`; the primary pair is at `+0x4568/+0x4570`. The first 32-byte-value map begins at `+0x3b28` or `+0x45a8`; the second 56-byte-value map begins at `+0x3b10` or `+0x4590`.

Earlier in each owner, a separate source sequence has an `0x58`-byte stride. If it is nonempty, the selected scalar and unrolled loops take the unsigned maximum `N` of the first word of each record. The old third marker words are `T3` and `V3`: if `(T3 & 1) != 0` and `N < V3`, they are preserved; otherwise the code stores `(1, N)`. An empty source sequence bypasses these marker writes. The sequence's application type and relationship to the first key vector are not established.

Later, a nonzero low byte at `+0x3af8` or `+0x4578` enables the third 32-byte-value map at `+0x3b40` or `+0x45c0`, using the saturating increment of the **stored** word at `+0x3b00` or `+0x4580`. The gate tests the whole low byte, not only its low bit. For synthetic independent maxima `M = N = 9` and old marker pairs `(1, 30)`, the first two maps receive cutoff 10, whereas the third receives cutoff 31. With an empty third source, its old marker can still enable the later split. `lane-layout.tsv` binds the tested and stored offsets to individual instruction bytes; all claims are conditional on the selected paths and normal returns.

### Partition, count and replacement

The selected search loops compare the requested cutoff and each 64-bit key as unsigned values, advancing while cutoff is greater. In a valid ordered depth-zero node, the first index whose key is greater than or equal to cutoff divides the node: a prefix stays in the old node and its suffix of keys and corresponding 32- or 56-byte opaque values is copied to the new node. Equality therefore belongs to the suffix. The accompanying 32-byte-value count helper compares the old and returned root depths as unsigned words. If the old depth is smaller it walks the old root; otherwise it walks the returned root. The selected walk starts with that root's 16-bit count, descends through child pointers, adds visited 16-bit counts, and follows parent/index links to the next child until it reaches a null parent; zero depth returns directly. For a well-formed tree with consistent depths and parent links, the counted side and the supplied original count determine the returned pair: `(counted_old, original - counted_old)` for the old walk, or `(original - counted_new, counted_new)` for the new walk. The selected branch and return bytes are recorded, and the low and shared count bodies are identical without masking. This conditional traversal description does not validate arbitrary malformed trees or prove how the original count was established.

In the depth-zero case this gives the old count minus suffix count and the suffix count. After that helper the parent calls the old-map cleanup boundary and installs the returned root, depth and suffix count. The separate cleanup of the old 32-byte-value maps is previously studied and is a boundary here.

For nonzero depth the split routines build a new spine, update child parent/index fields and take merge or redistribution branches. In the shared 32-byte-value split, the two pinned repair walks expose the following count decisions, assuming valid sibling counts `L` and `R` in `0..11` and normal return from calls:

| Selected condition | Right-side walk | Left-side walk |
| --- | --- | --- |
| `L + R + 1 <= 11` | Call the selected merge helper | Call the selected merge helper |
| `L + R + 1 >= 12` and the repaired side has at most 5 entries | Set right count to 6; set left count to `L - (6 - R)` | Set left count to 6; set right count to `R - (6 - L)` |
| `L + R + 1 >= 12` and the repaired side has at least 6 entries | Bypass that redistribution | Bypass that redistribution |

For example, `(L, R) = (6, 5)` enters right-side redistribution and writes `(5, 6)`; `(5, 6)` instead enters left-side redistribution and writes `(6, 5)`. The selection tests at `0x42883b3` and `0x428879c` and the subsequent count stores are in the generated byte windows. The moves around those stores also update separator keys and 32-byte values; later code handles child parent/index links when the selected depth is nonzero. This is a count-and-selected-write model, not a general proof of arbitrary tree inputs or all key and pointer rearrangements.

In the selected original- and returned-root collapse loops, when depth is nonzero and the current root's 16-bit count is zero, the first child replaces that root, its parent pointer is cleared, the depth is reduced, and the former root is passed with size `0x228` to slot `0x576e010`. The recorded call-site relocations and branch targets identify those operations, but the external slot's complete behavior is outside this packet. The selected right and left repair walks separately branch to length-bound `len > 0` assertion references when the checked child count is zero.

These observations support an ordered-tree interpretation. Full multilevel reachability, arbitrary malformed-tree behavior, allocation side effects and a general proof of every repair branch are not established. The focused synthetic models cover the stated depth-zero partition and the shared 32-byte sibling-count decisions only.

### Selected decisions and failure paths

| Condition | Byte-grounded continuation |
| --- | --- |
| Selected-key vector has zero entries | Skip the first two splits and continue at the third-map gate. |
| A selected map count is zero | Skip its split; the parent still invokes the old-header cleanup boundary and writes a zero root and zero count. The intermediate depth word is not claimed initialized on this path. |
| A selected map count is nonzero but its root is zero | The parent calls slot `0x576e470`, then jumps to a pinned `ud2` if the call returns. |
| Third flag byte is zero | Bypass that map's split; no statement is made about later unselected code. |
| Marker dword equals 2 at the checkpoint gate | Skip the corresponding previously studied checkpoint-admission call; other dword values reach it. |
| Initial or spine allocation returns zero | The selected 32-byte-value paths request failure handling with sizes `0x1c8` or `0x228`; the 56-byte-value paths use `0x2d0` or `0x330`. Each selected failure route ends in `ud2` if its helper returns. |
| A new right node is not empty, or a selected merge would exceed capacity | The corresponding bytes branch to length-bound assertion text and the pinned assertion-call slot. The semantics of the call target itself are outside scope. |

The four split FDEs have three parsed LSDA call-site rows each. The selected allocation-failure row in each has an action-zero landing at its terminal `ud2`; other personality decisions, action tables and unselected calls are not characterized. `literal-refs.tsv` derives 24 assertion references and their lengths from instruction displacements and immediates; their context pointers are retained as opaque addresses, not assigned source types.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo scope, two-build result, target execution, runtime fixture, helper closure and whole-ELF equivalence: not yet measured. The Python cutoff, third-source marker, depth-zero partition, merge and shared 32-byte repair functions are synthetic translations of the selected pinned instructions, not executions of the captured binary. The payload examples preserve opaque 32- and 56-byte values, but do not validate production object layouts or multilevel trees.

## Results and limitations

`summary.json` records 14 selected FDE ranges, 66 selected windows, 98 conditional branches, 60 calls, 3 failure jumps, 30 lane-layout operands, 24 literal references, 8 literal byte strings, 6 relocation records and 12 LSDA rows. These are selected records, not a component-wide coverage denominator. The focused suite has 47 passing tests and zero skips; it exercises vector maximum, empty and missing-root gates, byte-versus-dword gates, cutoff equality and saturation, old-marker precedence, both source sequences and the third cutoff, both leaf value widths, malformed keys, the merge limit, both sibling-repair directions and invalid counts, count-walk selection and returns, independent raw-offset and transfer decoding, bad digest, out-of-range and NOBITS mappings, ambiguous mappings, and corrupted FDE, index, byte windows, branch and call displacements, layout operands, literals, relocations and LSDA records. Independent regeneration with different hash seeds and time zones is byte-identical, including with a Python-only `PATH`.

This is an extension to an established path, not a recovered begin/action/end-block implementation or a complete state-root-input map. The upstream construction of the selected list, runtime scheduling, loader-result identity, full tree-repair closure, allocator/error behavior, all unselected branches and #115/visor remain open. No progress gate is requested; `abci` remains 0/4. Next, establish the object identity between the loader handoff and the worker receiver, then validate the multilevel split and cleanup paths without assuming the selected single-node model generalizes.
