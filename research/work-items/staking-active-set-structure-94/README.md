# staking: active-validator fallback set construction in node #94

This packet shows how the active-validator fallback obtains an independent, shape-preserving copy of the foundation-address tree and how its alternate key-collection path builds a sorted unique set, allowing a reconstruction to preserve tree ownership, node layouts, and failure boundaries before the fallback increments validator entries.

- Component ID: `staking`, validator lifecycle and stake accounting.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference was used only as a lead, not copied.
- Claim status: ELF bytes, unwind metadata, selected call sites, and bounded instruction-interpreter results are observations. The application names and chain-specific reachability below depend on the earlier packets identified under Inferences. Untested branches and external routines remain unresolved.
- Scope included and excluded: the four FDE-described windows in `functions.tsv` and the fixed caller-site bytes in `anchors.tsv`. The already studied active-set host and VoteGlobal union host provide context only; their complete bodies are not claimed again. Native node execution, actual allocator and sort implementations, all caller authorization, and other releases are excluded.

## Reproduce

From the repository root on Linux x86-64, using Python 3.12.3 and the standard library:

```sh
python3 tools/staking_active_set_structure94.py --out research/work-items/staking-active-set-structure-94
python3 -m unittest tests.test_staking_active_set_structure94
(cd research/work-items/staking-active-set-structure-94 && sha256sum -c MANIFEST.sha256)
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The generator verifies the full input digest first and reads section and FDE metadata through `tools/elf_index.py` and `tools/fde_extents.py`. It reads bytes, invokes no external program, and never executes the captured binary. Its instruction interpreter is adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`. To compare two clean outputs under different hash seeds and time zones, set `TMPDIR` to a writable temporary directory and run:

```sh
PYTHON_BIN="$(command -v python3)"
PATH='' PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/staking_active_set_structure94.py --out "$TMPDIR/active-set-a"
PATH='' PYTHONHASHSEED=713 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/staking_active_set_structure94.py --out "$TMPDIR/active-set-b"
diff -r "$TMPDIR/active-set-a" "$TMPDIR/active-set-b"
```

GNU objdump 2.42 was used only for human inspection; its output is not a generator input. `MANIFEST.sha256` binds this README and every generated evidence file. `functions.tsv` retains body hashes and FDE, CIE, LSDA, virtual-address and file-offset coordinates. `instructions.tsv` is a linear decode of each selected FDE, including rows not reached by the fixtures; it does not establish that every decoded row is reachable code. `transfers.tsv` records decoded direct transfers and conditional edges reached by unpatched normal or failure fixtures. `anchors.tsv` retains the exact context bytes, `foundation-inputs.tsv` the file-backed key fixtures, `relocations.tsv` the checked slots, and `scenarios.tsv`, `controls.tsv`, and `summary.json` the bounded results.

## Evidence

All addresses in this section are linked ELF virtual addresses; the tables also provide file offsets. Ends are exclusive unwind FDE bounds, not proof of all function boundaries or a whole-program denominator.

| Role | Selected FDE extent | Bounded result |
| --- | --- | --- |
| Recursive set clone | `0x33e47a0..0x33e4b68` | Copy every key into newly allocated nodes, preserve shape and count, and repair child parent/edge links |
| Map key iterator | `0x330f970..0x330fb64` | Walk the input map and return one key pointer at a time; zero remaining count returns null |
| Key collector | `0x3bb4d20..0x3bb4f28` | Collect keys, select a sort boundary, and pass the sorted vector to the builder |
| Set bulk builder | `0x2fbf100..0x2fbf983` | Build the set from sorted keys and collapse adjacent equal keys |

The previously studied active-set host tests a live flag at `0x3c11d6e`. When it is clear, a nonzero foundation-set count leads through the nonnull-root check to the clone call at `0x3c11d98`. A zero count instead leads to the collector call at `0x3c11e27`. The host then iterates the resulting set, obtains an entry in the selected-stake map, increments that entry with saturation, and returns the map; the respective context pins are `fallback_next_or_end`, `fallback_entry_and_saturating_increment`, and `fallback_return`. These are selected caller bytes and the established interpretation of `staking-stake-accounting-94`, not an independent execution of the whole host in this packet.

The bulk builder also has a direct call at `0x3bb4c00` in the already studied validator-key union path. That context is distinct from the alternate active-set branch and shows a second use of the selected builder; this packet does not rerun or reassign that host.

### Set clone

The source and destination set nodes use 20-byte keys beginning at node `+0x8`, parent pointer `+0`, parent edge index `+0xe4`, 16-bit key count `+0xe6`, and child pointers beginning at `+0xe8`. A leaf allocation requests `0xe8` bytes and an internal node requests `0x148`. In the bounded fixtures, a leaf with zero through 11 keys and structurally valid trees of heights one and two retain all key bytes, counts and exact shape. Child links point into the fresh output, parent backlinks and edge indexes match, and all original node bytes remain unchanged. The clone of a nonnull empty leaf still allocates an empty root; it is different from the collector's null-root empty output.

For a non-leaf, the function clones the first child, allocates the parent, then processes each key and following child. It rejects an output count at least 11 before another key copy, checks child heights, and checks the incremented child height for overflow. The failure calls are recorded boundaries, not evaluated panic implementations. Fixture trees supplied well-formed counts and child pointers; malformed high counts and allocator failures were separate negative controls.

### Collector and builder

The collector first multiplies the iterator's count by 20. Multiplication overflow or a result with its high bit set reaches the capacity-failure slot. A zero result makes no vector allocation. With one key no sort is called; 2 through 20 call the small-sort boundary, and 21 or more call the large-sort slot. The two sort functions are modeled as checked, lexicographic byte sorting; neither implementation is claimed here. The bulk builder is interpreted from its own entry with a supplied sorted vector. In the tested inputs it retains one copy of adjacent equal 20-byte keys and builds an ordered tree with correct parent and edge links. It grows a rightmost leaf and creates internal nodes as required, then checks the rightmost node against a minimum of five keys during final rebalancing. A direct builder fixture with 2,000 distinct keys reaches a height-three output. The fixtures check complete key order, count, parent links and node occupancy, not a unique tree shape for every valid input size.

| Condition or control | Observed boundary |
| --- | --- |
| Collector count zero | Null output root and zero count; the height word is not used |
| Collector count one | No sorting call |
| Collector count 2–20 / 21 or more | Small-sort / large-sort boundary, respectively |
| Collector count `461168601842738790` | Arithmetic guard passes; forced allocation failure reaches `0x3bb4ee5` |
| Next count or `u64::MAX` | Capacity failure at `0x3bb4d4f` before a successful allocation |
| Forced allocation failure in clone or collector/build | Reaches a recorded failure call; no rollback or cleanup guarantee is inferred |
| Duplicate adjacent input keys | One output key per distinct value in the tested sorted vectors |
| Corrupt key-copy, capacity, stride, duplicate-compare, or iterator-count instruction | Five one-byte controls yield a wrong result or a recorded rejection |

The accepted capacity example is an arithmetic edge, not an attempted allocation of that size: the allocator is intentionally failed. `controls.tsv` lists the individual failure sites. Distinct source trees use poison-filled unused bytes and deterministic, varied 20-byte keys. Three additional clone fixtures use the four, four and five 20-byte sequences read directly at the static coordinates in `foundation-inputs.tsv`; the fixture nodes are synthetic, and the association with chain lists rests on the earlier packet rather than a run of their initializers. A separate model produces expected sorted keys and, for clone fixtures, exact input shape. The interpreter checks source bytes, new node ownership and back-links. These are synthetic fixtures and do not establish live state reachability.

### Inferences

`staking-stake-accounting-94` identifies the caller's set as the foundation validator set and its result as the active-validator stake map. `staking-delegate-entry-94` identifies four or five foundation keys for the relevant chain-byte cases. On that earlier basis, the nonempty clone branch is the relevant fallback for those sets, while the empty-foundation collector branch is not shown reachable on those chains. The synthetic collector tests establish its instruction behavior under supplied iterator states, not its occurrence on a live chain. Likewise, the node's chain-3 name and the semantics of the larger validator-selection process come from prior evidence, not the clone bytes alone.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Rust build, lockfile, compiler/linker settings, two-build comparison, raw and normalized body comparisons, relocation and whole-ELF equivalence: not yet implemented/measured. No byte transplantation or operand normalization is used. The interpreter executes the selected bytes as a model, not as native target code. Allocation, deallocation, copying, sorting and failure sinks are checked fixture boundaries; the original implementations and unwind cleanup are not executed. No equivalence percentage or component progress gate is claimed.

## Results and limitations

- `summary.json` reports 221 normal scenarios, including three fixtures using static target keys, with zero mismatches and 28 additional controls: 20 forced allocation failures, three capacity controls and five byte mutations. The focused suite passes 24 tests with zero skips.
- Unpatched normal and fault fixtures reach 149 of 207 linearly decoded clone rows, 83 of 121 iterator rows, 117 of 135 collector rows and 329 of 443 builder rows. Conditional sites with both edges reached are respectively 6/15, 8/18, 8/10 and 21/39. Mutated executions do not contribute to those reachability numbers. These are fixture coverage figures, not a whole-component denominator.
- The sort calls, allocator, copy functions, failure sinks and unwind paths are boundaries. The selected iterator's malformed state and the builder's unsorted input are not claimed as safe. Deep unrolled iterator paths and other unreached branch outcomes remain open; source node counts, heights and links are assumed valid except in explicit negative controls.
- Only selected context bytes of the caller are checked. The existing active-set host and union host are not independently run from entry here, and their full transitive callees, dispatch and live reachability remain outside the packet. Node #115 is a separate target. No progress gate is requested.

Next question: independently reconstruct and compare the set clone and bulk builder in Rust, including multilevel allocation-failure cleanup and the large-sort boundary, against a separately authorized target-grounded harness.
