# RE-010: internal dispatch and batch-state slices in node 115

This packet maps a guarded node #115 internal byte-tag 17 arm through a nested dispatch to state-word updates, and separately traces related classifier and batch-processing branches.

- **Component ID:** `action-dispatch` (RE-010).
- **Target release and full SHA-256:** Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Source commit / reference commit:** repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed seed `999556f6e0a474b8312db96ec3149e1c44e97c23`, consulted for leads only. No reference source is copied into the tool or implementation.
- **Claim status:** the linked bytes, selected transfers, FDE records, immediates and stores below are observations. Function roles, action names and high-level data structure names are inferences. The relationship between the internal byte tag and the serialized Action enum, and a continuous transfer from this dispatcher to the batch core, are unresolved.
- **Scope included and excluded:** selected paths, constants, and normal-return branches in the 22 FDEs in `functions.tsv`; the full raw bytes of each are in `bodies.tsv`. This is not an exhaustive CFG, a function census, a complete cancellation implementation, a cross-release equivalence result, or evidence of committed transactions. Existing dispatchers and earlier first-call handler bodies are not selected here. No node or visor code is executed.

## Reproduce

From the repository root, with Python 3 and the checked-in common ELF/FDE readers:

```sh
python3 tools/re010_cancel_routing_115.py --out research/work-items/RE-010-cancel-routing-115
python3 -m unittest tests.test_re010_cancel_routing_115
(cd research/work-items/RE-010-cancel-routing-115 && sha256sum -c MANIFEST.sha256)
```

For a two-directory determinism check, substitute two distinct empty directory names for `FIRST-OUTPUT` and `SECOND-OUTPUT`:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re010_cancel_routing_115.py --out FIRST-OUTPUT
PYTHONHASHSEED=123 TZ=Pacific/Honolulu python3 tools/re010_cancel_routing_115.py --out SECOND-OUTPUT
diff -r FIRST-OUTPUT SECOND-OUTPUT
```

The extractor checks the complete target SHA-256 before interpreting the ELF. It uses Python `struct`, `tools/elf_index.py` and `tools/fde_extents.py`, excludes `SHT_NOBITS` when mapping file bytes, and invokes no external program. It checks each selected FDE start, end, unwind-header reference and complete body hash. Selected relative calls, the relative relocation, table displacements, instruction prefixes and immediates are decoded directly from file bytes. It writes only the generated files, leaving this README and manifest intact. `MANIFEST.sha256` records all files in this evidence directory except itself. The runs reported below used CPython 3.12.3 on Linux x86-64. The shared reader input hashes were `f142a7c03b0c2aee07d547cf93b0f6ef4b330b43ec61909d9388f340d0cdd70e` for `tools/elf_index.py` and `69798abfa12273bf8e3fa0be6e46dcb0a7807f2803287bbaa0916143ae527714` for `tools/fde_extents.py`.

GNU objdump 2.42 was used only to inspect candidate instruction sequences while choosing fixed sites. Its output is not an input to the extractor, tests or generated evidence. The extractor is deliberately not a general disassembler: full-body hashes tie the selected windows and manually interpreted instruction boundaries to this particular artifact.

## Evidence

Addresses are linked ELF virtual addresses; file offsets in the TSV files are zero based. For the selected executable sections, the listed code file offsets are the corresponding VAs minus `0x1000`; the tool derives mappings from section headers rather than assuming this relationship. FDE extents are half-open and are corroborated by the unwind header and selected call entries. An FDE extent is a machine-code boundary for this analysis, not proof of an original Rust function or a source-file boundary.

The maps below are deliberately separated. A shared callee is not proof that one root transfers control to another.

```text
internal tag 17:  0x2c47660 -> 0x2c4d2f0 -> 0x2c36770 -> 0x2c343b0
                                                   selected state +0x58 stores around 0x2c36af0
alternative arm:  0x2c4d2f0 -> 0x2c4eed0 -> 0x46aac00
other collector:  0x2608f40 -> 0x46aac00 and 0x26d59a0 -> 0x1cb5110
batch slice:      0x2c2c470 -> 0x231c580
                  0x2c2c470 -> 0x231d1c0 -> 0x2704e50 -> 0x2c6ad70
                  0x2c6ad70 -> 0x46aac00; 0x2c31910 or 0x2c31ae0
                  0x2c31910 -> 0x23cdb30 -> 0x23ce3e0 -> 0x23d4140
                  0x2c31ae0 -> 0x23cdf70 -> 0x23d0600 -> 0x23d3af0
```

These arrows denote selected static calls on their respective conditional paths. The two large finalizer bodies are retained in full, but only the selected call and nearby windows are interpreted. The tag-17 state path uses nested table index 3; the classifier arm uses nested index 0. The batch slice is independently rooted at its FDE; this packet does not prove the handoff from the tag-17 handler to that root. The `calls.tsv` records the exact site and displacement or RIP-relative relocation behind each arrow.

| Selected FDE start(s) | Observed role in the selected slice |
| --- | --- |
| `0x2c47660`, `0x2c4d2f0` | One-byte internal table dispatcher and its tag-17 target. |
| `0x2c36770`, `0x2c343b0` | Nested arm, its selected guarded call path, and context-word updates. |
| `0x2c4eed0`, `0x46aac00` | Alternate per-item check and shared state-dependent classifier. |
| `0x2608f40`, `0x26d59a0`, `0x1cb5110` | Independent group collector and selected tree-insertion helpers. |
| `0x2c2c470`, `0x231c580` | Batch limit, record conversion and a saturating state-word update. |
| `0x231d1c0`, `0x2704e50`, `0x2c6ad70` | Result allocation, per-item loop and conditional item routing. |
| `0x2c31910`, `0x2c31ae0` | Two kind-dependent route helpers. |
| `0x23cdb30`, `0x23cdf70` | Two lookup paths with child snapshots and recursive calls. |
| `0x23ce3e0`, `0x23d0600` | Finalizers reached after selected child traversals. |
| `0x23d4140`, `0x23d3af0` | Selected first and optional second zero stores. |

The exact ends, FDE/CIE/LSDA coordinates, body lengths and body hashes are generated in `functions.tsv`. The complete table lengths are not assumed: `tables.tsv` reads selected signed four-byte entries at ordinal 17 and nested ordinals 0 and 3. On this arm the first table target is `0x2c479ad`, the second is `0x2c48325`, and the later resumed dispatch target is `0x2c492d1`. The target at `0x2c492d1` reaches call site `0x2c49fa8` and handler `0x2c4d2f0` when the selected length guard passes. The first check accepts at most 100; the later check branches to the call for less than 101 and produces word `0x158` on its selected too-large path. Other lookups, authorization-like conditions, and intermediate failures must also permit reaching the call. The extractor's ordinal bound is only a bound on its own reads; it does not prove the runtime dispatcher accepts every smaller tag or safely rejects every larger tag.

At `0x2c4d2f0`, a selected state-byte check can return `0x91`, and a separate inner count of at least 10001 can return `0x158`. After additional checks, a normalized nested table index of 3 selects `0x2c4dd6b`, whose direct call reaches `0x2c36770`. That FDE checks an index against a state-like vector bound and takes a non-returning failure path if the bound fails; a count of at least 101 returns `0x158`, and a selected preparatory call must return `0x1a2` before the call at `0x2c36878` reaches `0x2c343b0`.

On a further selected normal-return path, `0x2c343b0` saves its incoming context pointer and eventually reads and stores its u64 word at offset `0x58`. The first store at `0x2c357a5` is a saturating increment. It then calls `0x2c36af0` with that context and, after a normal return, rereads the same word and stores a decrement floored at zero at `0x2c357f4`. The callback's effect on that word is unresolved, so the two stores cannot be assumed to cancel. `guarded-state-word-vectors.tsv` models the intervening value as an explicit synthetic input; the model does not assert the callback's effects or cover unwinding. These are context-word writes, with the business meaning and persistence of the word unresolved.

On the alternative nested index-0 arm, for items that reach its loop, a four-byte field from a 16-byte record is passed through `0x2c4eed0`. That helper calls the classifier and forwards a non-`0x1a2` word; its successful kind 1 branch returns `0x174`, while its selected kind 0 branch compares the quotient by 10000 against a supplied group and returns `0x156` on mismatch. This is a bounded account of these branches, not a complete list of handler failures.

The classifier's selected range partition is shown below. The input and adjustment are observed before state-dependent lookups; a kind-1 lookup can fail or return a state-derived value, so the table does not promise a final result. The rows around each boundary are regenerated in `asset-partition-vectors.tsv`.

| Input range | Pre-lookup path | Value supplied to that path |
| --- | --- | --- |
| 0 through 9999 | kind 0 | input |
| 10000 through 109999 | kind 1 | input minus 10000 |
| 110000 through 99999999 | kind 0 | input minus 100000 |
| 100000000 and above within u32 | kind 1 | input |

The independent collector at `0x2608f40` also uses the classifier: it rejects a count of at least 10001 with `0x158`, propagates a classifier failure, rejects successful kind 1 with `0x174`, and inserts distinct kind-0 group quotients into a temporary ordered structure. Its multiply-high by `0x346dc5d63886594b`, followed by a shift of 11, equals floor division by 10000 on the stated u32 model domain; the test includes an arithmetic bound and a wide deterministic sample. The selected allocation and insertion sites show an initial 104-byte allocation and a leaf threshold of 11. The exact source container type remains inferred.

For the independent batch root, the limit check precedes the batch core's own conversion and state stores. On a normal conversion return, the core adds the converted count to the u64 at state offset `0xb50`, saturating at the maximum u64. Under either of two selected predicates, it also copies an eight-byte and a four-byte value into state offsets `0x4288` and `0x4290`. The loop advances 32 bytes per converted item and 112 bytes per result. The core writes `0x1a2` after the result loop returns normally, even if individual result records carry errors; this is not proof of overall transaction commitment. A classifier kind-1 path with the byte at state offset `0x42ac` nonzero produces `0x108`; selected precheck failures produce `0xc9`. At `0x2c6b208`, the per-item `0x1a2` path increments the u64 at `0xb58` with saturation. The business meaning of these words is not established by the stores alone.

On selected successful lookup paths in both recursive helpers, 20 bytes are compared, a child list is copied, each eight-byte child is recursively visited, and the corresponding finalizer is called after the loop. The recursive call's return is not checked before proceeding to the next child; after the finalizer returns normally, the helper sets a return byte to 2. The two finalizers each have a selected call to their respective link-clear helper. On a selected lookup and key match, that helper reads the old low 32 bits of a word and clears the full eight-byte word at offset `0x20`; only if the old low bits equal 1 does it continue to another lookup, where a matching second record can have its word at offset `0x20` cleared. An absent or nonmatching second record can therefore follow the first store. No rollback or persistence conclusion follows from these static stores.

`windows.tsv`, `branches.tsv`, `calls.tsv`, `relocations.tsv`, `constants.tsv` and `tables.tsv` retain raw selected bytes and coordinates. The `*-vectors.tsv` files are explicitly synthetic models and boundary controls, not target execution captures. The lookup graphs supplied to the walk model are finite and acyclic; they do not establish behavior for arbitrary live state. The two-clear model assumes its boolean inputs summarize completed lookups and key comparisons.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build flags, Cargo dependency closure, two-build reproducibility, byte comparisons, normalization masks, relocation/data closure and whole-ELF equivalence: **not yet measured**. The tests compare selected decoded instructions and mathematical models against authenticated bytes and include corrupted digest, body, FDE, table, branch, relocation, byte-range and model-input controls. They do not run the node or compare behavior with a live process.

The unlicensed reference's handler-file split is a search label, not evidence that any one reference file is an original binary function. The earlier cross-release survey is background only; no #94 function body, layout, status or coordinate is transferred as a #115 fact. There is no byte-equivalence claim between releases.

## Results and limitations

The generated summary records 22 selected FDEs, 88 selected windows, 114 conditional branches, 28 calls, three dynamic relocations and five selected table entries. These are denominators for the selected evidence only, not coverage of the whole ELF. The focused unittest suite ran 56 tests with no skips. Deterministic regeneration and repository checks are recorded in the accompanying draft.

This packet requests no component gate change: `action-dispatch` remains 0/4. The relation of the byte tag to a serialized Action name, the separate tag-17-to-batch handoff, complete failure and unwind behavior, the callback and finalizer internals, exact business meanings and transaction rollback remain open. Next question: independently bind this internal byte-tag producer and the already studied intervening boundary to the batch root without attributing unexamined actions or overwriting existing evidence ownership.
