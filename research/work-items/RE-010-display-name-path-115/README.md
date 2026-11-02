# RE-010: Trace the node 115 display-name dispatch path

Node #115 routes internal tag `0x99` to a direct `setDisplayName` handler, while the corresponding nested action uses a separate dispatcher and wrapper before reaching the same state core; this distinction lets a reconstruction preserve both paths and their result encodings.

- Component ID: `action-dispatch` (RE-010).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; investigative reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead, not implementation source.
- Claim status: static observations below; names and container behavior are explicitly identified as inferences; wire admission and full helper closure remain unresolved.
- Scope included and excluded: one action through its direct route and the selected nested route, result branches and storage mutation. Other actions, all possible callers, execution, chain state, and a reconstructed Rust implementation are excluded.

## Reproduce

From the repository root with Python 3.10 or newer, the authenticated target, and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/display_name_path_115.py --out research/work-items/RE-010-display-name-path-115
python3 -m unittest tests.test_display_name_path_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For a two-environment comparison, set `TMPDIR` to a writable temporary directory and run:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/display_name_path_115.py --out "$TMPDIR/display-a"
PYTHONHASHSEED=987 TZ=Pacific/Honolulu python3 tools/display_name_path_115.py --out "$TMPDIR/display-b"
diff -r "$TMPDIR/display-a" "$TMPDIR/display-b"
```

The tool checks the input digest before parsing. It reads file-backed ELF sections, indexed FDEs, relocations, fixed instruction windows and signed displacements; it neither invokes another program nor executes a captured binary. `windows.tsv` contains raw bytes, and `MANIFEST.sha256` hashes this packet's files. Investigative disassembly used GNU objdump 2.42 and Python 3.12.3 on Linux x86-64; neither objdump output nor its formatting is an input to the generator or tests. The generator needs only the standard library and the two shared parsers.

## Evidence

All addresses below are linked ELF virtual addresses; `functions.tsv`, `windows.tsv`, `edges.tsv`, `indirect-edges.tsv`, `switch-tables.tsv`, and `name-tables.tsv` also record file offsets. Ends are exclusive. FDE ranges are unwind descriptions; direct calls, entry instructions, and the selected returns corroborate the callable entries but do not establish complete source-level boundaries or rule out split cold code.

| Selected role | Indexed FDE range | Path evidence |
| --- | --- | --- |
| Action router | `0x2bda7c0..0x2bdb225` | Index 19 calls the direct handler; index 52 calls the nested outer caller. |
| Direct display handler | `0x2c08600..0x2c08ac8` | Performs the key checks, gates and length guard, then calls the display core. |
| Nested outer caller | `0x2c12690..0x2c12c09` | Calls the selector, two gates and nested dispatcher; has an earlier key-match rejection. |
| Action classifier | `0x36c30f0..0x36c3175` | The caller's relocation resolves to this function; selected arm returns zero. |
| Action selector | `0x2bdb5b0..0x2bdb911` | Selected arm returns the success word and an empty collection. |
| First gate | `0x2c202b0..0x2c206ab` | Empty selector output takes the success return. |
| Second gate | `0x2c206b0..0x2c20a84` | The selected empty iterator reaches its success return. |
| Formatter | `0x2bc95f0..0x2bcbbe1` | Its selected arm refers to `setDisplayName`. |
| Dispatcher | `0x2bdbaa0..0x2bdcb65` | The selected arm `0x2bdc64d` is inside this FDE, not a separate handler entry. |
| Display wrapper | `0x2392200..0x2392308` | Its caller is the arm's direct call at `0x2bdc670`. |
| Display core | `0x2c76380..0x2c766dc` | The wrapper calls it at `0x239228d`. |
| Erase / upsert | `0x2dcd870..0x2dcdd07` / `0x2dbff30..0x2dc06d2` | The core calls these at `0x2c76413` and `0x2c76685`, respectively. |

The formatter, router and nested dispatcher each subtract `0x86` from a loaded discriminant and use a relative jump table. At index 19 the formatter table entry is at `0x6094b8` and targets `0x2bcb2d4`; the arm's instruction at `0x2bcb316` points at the 14-byte literal `setDisplayName` at `0x60c546`. The selected internal discriminant is `0x86 + 19 = 0x99`. The router's index-19 target `0x2bdaf4c` calls `0x2c08600`, which calls the core directly at `0x2c08a0d`. By contrast, the nested dispatcher table entry at `0x60a3ac` targets `0x2bdc64d`, which calls the wrapper at `0x2392200` before the core. Treating the agent's single handler file as one original function would miss this distinction.

The router's index-52 target `0x2bdb07a` calls the nested outer caller. At that same index the formatter arm `0x2bcb7c7` refers to `multiSig`; the nested outer caller loads a child action pointer from its input at offset `0x18` for classification and selection. The nested dispatcher receives the parent input, loads that pointer again, and reads the child's tag. A child with tag `0x99` therefore follows the selected nested path. The name-to-execution connections infer that these switches consume the same enum representation; the decoder-to-dispatch handoff is not traced. Three separately relocated name arrays agree at the selected indices and each has a `variant index 0 <= i < 92` sentinel. The 460 switch entries in `switch-tables.tsv` are the 92 in-range entries of each of five tables; only the two named connections above are analyzed here. Co-listing the other names by position in `switches.tsv` is not a claim that their semantic mapping has been verified.

On the direct path, the handler can inspect two 20-byte keys against a state collection. An equal comparison branches to `0x2c0885a`, which writes word `0x120` and outer tag `0x0f`. Otherwise, it constructs an empty collection and calls the two gates before the local length guard. On the nested path, the classifier returns zero for the child discriminant, enabling the analogous key checks; equality branches to `0x2c12a70` and writes the same word and tag. Which real-world principal each key represents is unresolved. If that prior rejection does not occur, the nested selector's index-19 arm writes zero at output offsets `0x8` and `0x18`, along with word `0x1a2`; it does not initialize every byte of that output. For either empty input, the first gate returns `0x1a2`; the second constructs a zero-count iterator, whose empty return is checked at `0x2443a40`, and also returns `0x1a2`. Generic failure continuations from the selector and both gates are recorded in `edges.tsv`; the selected empty cases do not take them.

Each route preserves its original third argument across the preliminary work and copies 20 bytes from it into the call to the core. On the nested path the copy passes through the dispatcher and wrapper; the direct handler makes its own copy. The preliminary second key is not substituted at these forwarding points. This is a register-and-byte observation; the public account identity associated with that argument is an inference.

The following table describes normal returns for both routes, after any prior rejection and assuming the allocation-like call succeeds. Length is the byte count loaded from the selected payload; the copy uses the relocated `memcpy` slot. The success word is internal: the direct handler and the nested wrapper each write outer tag `0x0e` on that word and outer tag `0x0f` with an error payload otherwise.

| Condition, in decision order | Internal word | Display-state operation |
| --- | --- | --- |
| Either earlier key comparison matches | `0x120` | The core and nested dispatcher are bypassed. |
| Wrapper length at least 101 | `0x158` | Core is bypassed. |
| Length zero | `0x1a2` | Call erase with the copied 20-byte key. |
| Length 21 through 100 | `0x00e2` | No erase or upsert. |
| Length 1 or 2 | `0x00e3` | No erase or upsert. |
| Length 3 through 20 and an equal stored value is encountered | `0x00e4` | No erase or upsert. |
| Length 3 through 20 and no equal stored value is encountered | `0x01a2` | Call upsert with the copied key and the owned value. |

The core checks lengths before scanning, checks equal lengths before the relocated `bcmp`, and makes no visible key comparison to exclude the caller's own record from either the compact scan or the tree-value iterator. Under valid container invariants this implies that submitting one's unchanged existing value is rejected as a duplicate. `branch-vectors.tsv` is a synthetic evaluation of these recorded predicates, not a captured execution or differential test.

At the core's second argument plus `0x3f88`, the erase and upsert routines operate on a keyed container. In the compact representation the code steps by 48 bytes and compares 20-byte keys. A found key reaches replacement stores at `0x2dc0502`; an absent key reaches `0x24bda40`, which shifts records, increments a count, and copies a 48-byte record. The shift helper reaches a relocated `memmove`. When an absent-key insertion sees a count at least 64, the upsert path enters a representation conversion; the sentinel `0x8000000000000000` selects the tree path. The tree insertion path includes an empty-node allocation request of `0x1f0` bytes and a local bound check of 11; the tree erase helper decrements its count at `0x26e0c6f`. These details describe selected machine-code paths, not a complete recovered container implementation. Bounds and allocation failure edges are retained in the evidence rather than reclassified as ordinary action errors.

### Historical lead and cross-release boundary

The retired #94 packet `research/work-items/RE-010-exchange-handlers/README.md` at repository commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4` reports node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, case 19 at dispatcher arm `0x2759ee6`, and a first call to `0x27e2170` from dispatcher `0x2759240`. Those are historical #94 claims, not #115 coordinates. This packet independently derives the #115 table, call, FDE and literal above from the #115 bytes; it does not assert binary equality or independently re-run the retired artifact. The reference file `handlers/19_set_display_name.rs` is an agent-created semantic split and is not evidence that one original #115 function starts at that file boundary.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Compiler and linker settings, two-build comparison, normalization masks, helper and relocation closure, and whole-ELF comparison: **not yet measured**. The selected windows are raw and unmasked. The tool verifies 23 indexed FDE records, 77 pinned windows, 73 selected direct edges, 16 selected indirect edges, and 8 relocations. These are selected evidence counts, not a function-coverage denominator. The tests include altered digest, instruction, FDE index, switch target, name bytes, relocation and non-file-backed address controls.

## Results and limitations

The targeted unittest module passed 21 tests with no skips. Separate generator runs with different hash seeds and time zones produced identical evidence, including with a PATH lacking binutils. Artifact/signature verification and catalogue consistency were checked separately. No captured binary was run, and no progress gate is requested.

The 92-entry tables do not prove external wire decoding or validation of all variants. The selector's empty case and the normal mutation paths do not establish all allocator failures, malformed in-memory structures, tree rebalancing, cold/unwind paths, or effects before the selected caller. The old and new binaries have not been compared for semantic equivalence. Next, identify the actual #115 decoder-to-dispatch handoff and independently validate the remaining tree helper cases before implementing and comparing this action in Rust.
