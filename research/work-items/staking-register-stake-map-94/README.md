# staking: validator registration stake-map insertion in node #94

This packet recovers how validator registration creates a zero-valued stake row and propagates insertion through the ordered stake map, including split pivots, returned cursor, count ownership and failure boundaries, so a reconstruction can preserve the row and tree shape when a new validator enters an existing map.

- Component ID: staking, validator lifecycle and stake accounting; the #94 half of the component's first task.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference is a lead only and no reference code was copied.
- Claim status: observation for instruction bytes, FDEs, fixed call sites and modeled byte execution; inference for application-level names and their connection to the enclosing registration action. Unresolved behavior is listed below.
- Scope included and excluded: two complete FDE windows, `0x33bede0` and `0x2f54330`, and selected incoming instruction witnesses in the already studied caller. The enclosing validator action, authorization and profile gates, duplicate search as a complete function, allocator, copy routines and unwind bodies are excluded. Node #115 and Rust implementation are excluded.

## Reproduce

From the repository root with Python 3.12.3, Linux x86-64 and the authenticated artifact:

```sh
python3 tools/artifacts.py verify
python3 tools/staking_register_stake_map94.py --out research/work-items/staking-register-stake-map-94
python3 -m unittest tests.test_staking_register_stake_map94
python3 tools/catalogue.py --check
(cd research/work-items/staking-register-stake-map-94 && sha256sum -c MANIFEST.sha256)
```

To compare independent regenerations, use a writable directory represented by `<tmp-dir>` and a directory containing Python but no binutils represented by `<python-only-bin>`:

```sh
mkdir -p <tmp-dir>/one <tmp-dir>/two
TMPDIR=<tmp-dir> PATH=<python-only-bin> PYTHONHASHSEED=17 TZ=UTC python3 tools/staking_register_stake_map94.py --out <tmp-dir>/one
TMPDIR=<tmp-dir> PATH=<python-only-bin> PYTHONHASHSEED=917 TZ=Pacific/Honolulu python3 tools/staking_register_stake_map94.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The standard-library tool checks the target digest first and imports the repository's `elf_index` and `fde_extents` parsers. It reads only file-backed sections, FDE/CIE records, relocations and fixed instruction bytes. It executes an interpreter over bounded synthetic memory, not the node, and starts no external program. Its decoder is adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`. GNU objdump 2.42 was used only for human inspection; its output is not a generator input. The twelve generated files and their hashes are in `MANIFEST.sha256`; tool and test files are outside the evidence-directory manifest.

## Evidence

Addresses are linked ELF virtual addresses. `functions.tsv` includes file offsets, actual FDE/CIE coordinates, exclusive ends and full unmasked window hashes; `instructions.tsv` retains the raw linearly decoded bytes. FDE extents delimit the selected unwind ranges, not a census of all functions. Linear decoding alone does not show reachability.

| Selected entry | FDE end | Observed role |
| --- | --- | --- |
| `0x33bede0` | `0x33bef2a` | Empty-root setup or delegation to the nonempty-tree insertion, followed by map-length increment and cursor return. |
| `0x2f54330` | `0x2f54f90` | Insert a 20-byte key and two 64-bit value words at a supplied vacant cursor, with leaf and parent splits. |

The earlier stake-accounting and validator-entry packets identify the state at `S+0x10` as the validator-to-stake map. Their interpretation is reused, rather than independently established by these two helpers. The context witnesses show a profile gate result compared with `0x186`, a root load at `S+0x10`, a 20-byte comparison through the slot bound to `memcmp`, and an equal-key branch to a `0x93` status. On the vacant path, `0x3995703` clears both value argument registers and `0x3995707` calls the selected entry. `anchors.tsv` preserves these context bytes and `relocations.tsv` binds the comparison slot. The enclosing caller was inspected only at the recorded sites; it was not entered in the interpreter and its other branches are not claimed here.

| Condition or operation | Byte-backed continuation |
| --- | --- |
| Empty map root | The entry allocates a leaf of `0x198` bytes, initializes its parent and count, writes one key and both supplied words, and increments map length. |
| Existing vacant cursor | The entry calls `0x2f54330`; the caller supplies the gap and the helper does not itself perform duplicate-key search. |
| Leaf has fewer than 11 keys | The helper shifts later keys and values, inserts the pair, and increases the node count. No new node is allocated in the tested cases. |
| Leaf has 11 keys | A new leaf is allocated. For insertion gaps 0–4, 5–6 and 7–11, respectively, old keys 4, 5 and 6 are promoted. The incoming key remains in a child. |
| Ancestor has room | The promoted pair is inserted into that ancestor and propagation stops. |
| Full ancestors reach root | Splits propagate upward; a new internal root is allocated, the map root and height are changed, and child parent/edge links are repaired. |
| Successful insert | The inner helper leaves the map count unchanged; its entry wrapper increments it once and returns a cursor to the inserted pair. |
| Modeled allocation failure | Allocation returns null and the machine reaches the recorded failure sink for the relevant leaf or internal-node size; subsequent panic/unwind behavior is not modeled. |
| Malformed fixture descriptor | Selected bad count, missing-root and inconsistent-height fixtures reach the distinct recorded failure sinks. They do not establish that valid state reaches them. |

The key array starts at node `+0xb8`, with 20-byte elements; the value array starts at `+0`, with 16-byte elements. Parent pointer, parent edge and occupied count are at `+0xb0`, `+0x194` and `+0x196`. An internal node adds the child array at `+0x198` and has allocation size `0x1f8`. The separate map's root, height and length occupy three consecutive words. The entry's `+0x10` increment belongs to that map, not the node count. `anchors.tsv` and the complete decoded windows provide the individual load, copy and store bytes.

The separately written sorted-tree model checks every logical key and both opaque value words, the complete resulting tree shape, parent links, split allocation order and returned cursor. It does not use the binary's split implementation. The adapter is also entered with the registration-path zero value and with nonzero word patterns. Tests provide the vacant cursor; the outer search is not simulated. Boundary cases include all leaf positions, all full-leaf gaps, full and partially full parents, selected cascades through three ancestors, and null allocations. `cases.tsv`, `adapter-cases.tsv`, `branches.tsv`, `branch-mutations.tsv`, `failure-cases.tsv`, `failure-edges.tsv`, and `mutations.tsv` retain results and reachability. Six independently applied byte edits change capacity, pivot, a branch, key copying, a value store and the map-length offset; each is detected by a previously passing fixture. A model fault is a test detection, not a claim about a corrupted node process. Separately, each insertion conditional was inverted once per normally observed edge using one reaching fixture, after the unedited fixture passed with the same step limit. Of 60 samples, 40 stop in the model, 16 reach a hooked failure sink and four still match the model. The four survivors at `0x2f54375`, `0x2f545f8`, `0x2f5498e` and `0x2f54c6a` were not analyzed further; a survivor is not proof of equivalence. `branch-mutations.tsv` retains each fixture and outcome.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker settings, two-build result, native differential execution, raw/normalized compiled comparison and normalization masks are not yet measured. No original machine code is transplanted. Allocation and memory-copy calls are fixture hooks, while deallocation and failure sinks are stop boundaries; selected direct calls between the two recovered windows execute in the interpreter. `relocations.tsv` identifies the relevant ELF slots; their implementations and unwind cleanup remain outside this comparison.

## Results and limitations

The generated summary records 974 direct insertion fixtures and 180 entry-wrapper fixtures, with no model mismatches; 10 malformed or null-allocation fixtures reach their expected modeled failure sites, and six targeted mutations are detected. The normal fixtures reach 603 of 673 decoded insertion instructions and both edges of 22 of its 38 conditional instructions; they reach 73 of 80 entry instructions and both edges of 1 of its 3 conditionals. `branches.tsv` separately records the extra edges reached by failure fixtures. These are selected-window and fixture counts, not component coverage or a proof of all control flow. The focused suite passes 25 tests without skips; two regenerations under different hash seeds and time zones with binutils absent from `PATH` are byte-identical.

Application field names and the registration interpretation depend on the earlier serializer and action packets. The host's remaining guards and other callers are not recovered here. Tests do not establish behavior for duplicate insertion through a malformed cursor, arbitrary invalid trees, every unreachable branch, real allocator failure cleanup, or live chain states. No component progress gate is requested. Next question: independently implement the stake-map insertion and registration integration in Rust, including allocation/unwind ownership, and compare it with the target once an authorized differential harness exists.
