# RE-017: node 115 post-block cursors and keyed row pipeline

This packet determines how a loader-linked post-block continuation walks two tree-backed state collections in reverse and how its later keyed-row pipeline searches, sorts, and retains the last row in each adjacent duplicate run, enabling an independent reconstruction to preserve these transitions and their failure ordering.

- Component ID: `abci`; the selected state and snapshot question also supports RE-009.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed navigation reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was not copied. Historical packet `RE-017-abci-state-link-94` is separately bound to its #94 digest below.
- Claim status: target bytes, operands, relative transfers, relocations, FDE/CIE and LSDA records are observations. The tree, ring, collection and pointer-flow interpretations below depend on the explicitly stated valid-layout, ordering, binding, alias and normal-return conditions. Reachability, source-language types, and the whole component are unresolved.
- Scope included and excluded: two reverse cursor FDEs, an associated selected lookup and ring search, two row collectors, their selected preparation wrapper, two short sorters and two compactors, plus small contextual windows in the already proposed caller. The prior loader, its GOT/call sites, callback, block engine, outer collector, comparator implementation and large sorters are existing boundaries, not newly owned functions. This packet is not a complete process-entry, begin/action/end-block, state-root, or component reconstruction.

## Reproduce

Run from the repository root with the authenticated #115 artifact present. Output directories should be empty before the first generation:

```sh
python3 tools/abci_tree_cursor115.py --out research/work-items/RE-017-abci-tree-cursor-115
python3 -m unittest tests.test_abci_tree_cursor115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
mkdir -p work/re017-python-only
ln -s "$(command -v python3)" work/re017-python-only/python3
PYTHONHASHSEED=1 TZ=Etc/UTC PATH=work/re017-python-only python3 tools/abci_tree_cursor115.py --out work/re017-cursor-a
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu PATH=work/re017-python-only python3 tools/abci_tree_cursor115.py --out work/re017-cursor-b
diff -r work/re017-cursor-a work/re017-cursor-b
diff -r -x README.md -x MANIFEST.sha256 work/re017-cursor-a research/work-items/RE-017-abci-tree-cursor-115
PATH=work/re017-python-only python3 -m unittest tests.test_abci_tree_cursor115
(cd research/work-items/RE-017-abci-tree-cursor-115 && sha256sum -c MANIFEST.sha256)
```

With the separately authenticated historical artifact available, the following additional check verifies its original FDEs, Location, indirect-call slot and comparison before writing the **same** #115 output:

```sh
python3 tools/abci_tree_cursor115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-cursor-history
diff -r work/re017-cursor-a work/re017-cursor-history
```

Python 3.12.3 on Linux x86-64 produced the records. The generator authenticates the whole input before parsing or creating its output and uses the repository's `elf_index.py`, `fde_extents.py`, and Python standard library. It rejects ambiguous and non-file-backed mappings, including `SHT_NOBITS`. Neither generator nor tests invokes an external program. GNU objdump 2.42 was used for human inspection only; its output is not parsed or included in generated records. No captured executable, network service, key, or chain operation was used. The supplied index metadata names the same #115 digest; regeneration with the repository indexer matched its TSV and JSON byte for byte.

## Evidence

All addresses below are linked ELF virtual addresses before any load bias; generated records also contain file offsets. The FDEs are unwind-described ranges, not proof of source-level boundaries or a complete function census. `functions.tsv` and `extra-functions.tsv` retain the full raw bytes and hashes of the 11 newly selected FDEs, and `windows.tsv` partitions the two cursor bodies without gaps. `transfers.tsv`, `family-edges.tsv`, `extra-points.tsv`, `descent.tsv`, `layout.tsv`, `search-layout.tsv`, the Location/relocation files and both unwind tables derive their numbers from the authenticated ELF. The 38 windows in `context.tsv` are explicitly prior-function context.

### Selected connection and ownership

The earlier, unmerged loader handoff proposal #2047 connects a #115 `state.rs` Location to a selected startup result; #2243 and #2332 propose the later owner, block-callback and post-block collector connection. Their assumptions and ownership remain separate. In the selected collector `0x4dfe6d0`, source fields `+0x1a48` and `+0x1940` feed the two paths below, and the third source begins at `+0x19a8`. The tree-specific contextual calls at `0x4dfeba8` and `0x4dfee43` target the newly examined cursor FDEs; the first two sources also have contiguous-array routes. The caller stops each selected stream when the returned key pointer is null or its unsigned first word is at most the saved watermark. In the second stream a null value field causes a skip, not termination. Its tree value test is at returned value pointer `+0x28`; in the contiguous 80-byte row it is at row `+0x30`. The previously examined caller later conditionally writes the selected collected maxima at callback-subobject `+0x2d0` and `+0x2d8` only for nonempty collections. These caller instructions and existing loader calls are checked as context, not claimed again.

| Newly examined FDE | Role in this selected continuation |
| --- | --- |
| `0x514e3c0..0x514e674` | Reverse cursor for the first tree-backed source. |
| `0x514e680..0x514e934` | Reverse cursor for the second tree-backed source. |
| `0x4d55e30..0x4d55f92`, `0x5ba4680..0x5ba4999` | First preparation and collection stage for the later keyed-row path. |
| `0x53d78c0..0x53d7af1`, `0x57fc1b0..0x57fc37b` | Selected nested lookup and its ring-backed 20-byte-key search. |
| `0x5ba41c0..0x5ba4680` | Second collection stage, including its explicit early termination and allocation boundaries. |
| `0x53efb10..0x53efc11`, `0x53ec830..0x53ec931` | Short-input sorters for the first and second row stages. |
| `0x5b2d1d0..0x5b2d308`, `0x5b2d510..0x5b2d648` | Compaction for the two row stages. |

The third-source path is selected when the prior caller's byte at stack `+0xf` is zero; the other arm bypasses that preparation. The two watermark stores occur after additional calls. The argument that these observations describe one loader-fed instance requires the prior proposals' selected joins and stability of all relevant pointers and buffers; matching offsets alone do not prove instance identity.

### Reverse cursor transition

Each cursor's descriptor uses a 32-bit tag at `+0x20`, current node at `+0x28`, a root or depth word at `+0x30`, an index or initial depth at `+0x38`, and a remaining count at `+0x40`. These offsets are decoded from actual operands in `layout.tsv`. The return registers on the nonempty selected path are a key pointer in `rax` and value pointer in `rdx`.

| Condition | Byte-backed transition |
| --- | --- |
| Remaining count is zero | Return a zero key pointer before the tag check; no descriptor decrement occurs. The other return register is not assigned a meaning on this arm. |
| Remaining count is nonzero | Decrement `+0x40` **before** checking whether the low 32-bit tag equals 1. A different tag enters a Location-bearing failure boundary. |
| Current node is null | Treat `+0x30` as the initial root and `+0x38` as depth; follow the node's rightmost child for that depth, then store the selected node, reset the depth word and set the index to that node's 16-bit length. |
| Current index is nonzero | Use that node and index directly for the returned key/value pair; update the descriptor to the preceding position. |
| Current index is zero | Follow parent pointers, using each child's 16-bit parent index until one is nonzero; the corresponding parent entry is returned. A missing parent reaches a separate Location-bearing failure boundary. |
| A parent was climbed | Before returning the parent entry, select its immediately preceding child and follow rightmost children for the remaining climbed depth; store that node and its length for the next step. |

For a selected parent and nonzero index `i`, the key address is parent `+ 8*i`. The value address is parent `+0x60 + (i-1)*stride`. The first cursor's stride is 24, its node's parent-index/length/child-base offsets are `+0x168/+0x16a/+0x170`; the second cursor uses stride 72 and offsets `+0x378/+0x37a/+0x380`. The child selected after climbing is at `parent + parent-index-offset + 8*i`. Both initial and predecessor-subtree descents split their step count into a remainder modulo 8 and an eight-step loop. `descent.tsv` verifies every unrolled length and child load in both cursor bodies; it is not an instruction census for other functions.

Under a valid finite tree, consistent parent links and child indexes, immutable keys and ordinary machine arithmetic, these equations enumerate entries in reverse structural in-order. If the keys are ordered by the caller's unsigned comparison, stopping at the first key at most the watermark yields the full qualifying suffix; that ordering is a precondition, not established for every state object. The #115 failure Location records have the relative suffix `library/alloc/src/collections/btree/navigate.rs` at 546:52 and 166:35. They support a B-tree navigation interpretation but do not prove a particular public-source revision or ABI.

### The keyed row continuation

On the selected later path, `0x4d55e30` passes the third source through `0x5ba4680`. A 64-byte contiguous-source stride and its alternate iterator route are visible in that collector. For each selected source row it calls `0x53d78c0` with a shared 20-byte search key and a row-derived candidate. A nonzero returned pointer admits a 32-byte intermediate row: 20 observed key bytes, four additional copied bytes whose meaning is unresolved, and the returned pointer at `+0x18`. A null result is skipped. The helper's tree-shaped and ring-shaped lookup arms are visible; the complete construction and mutation of their source containers remain open.

On its ring arm, the descriptor at `0x57fc1b0` has capacity, buffer, head and length at `+0/+8/+0x10/+0x18`, respectively. It uses 32-byte rows and compares 20 key bytes through a dynamic relocation naming `memcmp`; the value pointer selected by `0x53d78c0` is row `+0x14`. For a well-formed, sorted ring, the selected search distinguishes empty, contiguous and wrapped storage, searches the appropriate segment, returns tag 0 with a matching logical index on a hit and tag 1 with an insertion index on a miss. A duplicate-key hit is not claimed to be the first equal row. Runtime symbol binding and the validity, order and lifetime of the input storage remain assumptions.

After the first stage's selected sort and compaction, the second collector `0x5ba41c0` reads the retained pointer. A null pointer or a zero dword at that pointer takes an exit from this collector; it does not continue past that row. On the selected nonzero path it forms another 32-byte row with the original 20-byte key, that dword at `+0x14`, and the following eight bytes at `+0x18`. Both the first and subsequent zero tests are pinned. Whether any valid loader-fed value reaches those exits is unresolved. On ordinary successful returns, the later caller packages this result alongside the other collected data; complete contents and side effects of the surrounding calls are not established.

The two small sort/compaction stages have the following byte-backed decisions:

| Count or comparison | Selected operation and limit |
| --- | --- |
| Count 0 or 1 | Bypass the short sorter; compactor returns without changing length. |
| Count 2 through 20 | Call the selected insertion-sort FDE, comparing the first 20 bytes; with ordinary `memcmp` semantics, equal keys retain their incoming relative order. |
| Count 21 or more | Call a separate indirect large-sort boundary. Its ordering and stability are not proved here. |
| Equal adjacent 20-byte keys | Swap whole 32-byte rows and retain the later row in the output prefix; repeat for a run. Unequal keys are compacted forward, and the final prefix length is stored. Only adjacent equal keys are removed. |
| Result count at most 64 / greater than 64 | The caller selects different representation boundaries. Their full semantics are outside this packet. |

The two compactor bodies are raw identical. The short-sort bodies match after zeroing only relative offsets `0x4a..0x4d`, the respective RIP-relative displacements to the same observed `memcmp` slot. `families.tsv` gives the explicit mask and normalized hash, and `extra-functions.tsv` retains both unmasked bodies. This is a comparison of two original #115 bodies, not a source-build or whole-binary equivalence claim. Under a normally bound comparator and unchanged rows, a small sorted duplicate run therefore retains the row that was last **in that collector's input order**. For unsorted inputs, nonadjacent duplicates remain; for the large sorter, grouping and tie order are not established.

### Failure and unwind boundaries

For both reverse cursors, an unexpected nonempty tag and a missing parent reach separate calls through the same selected relative slot; returning from either call reaches `ud2`. `unwind-calls.tsv` records that the missing-parent call's LSDA row names the later `ud2` as its landing, whereas the tag call's row has no landing. This is recorded metadata, not a guarantee of a particular runtime unwind or its completion.

The first row collector's initial allocation-failure call is distinct from the later growth call. In the second collector, the checked size guard and a null allocation lead to the common failure boundary, followed by `ud2` if that boundary returns. `extra-unwind.tsv` records all 18 selected LSDA call-site rows from the three larger FDEs; `extra-unwind-calls.tsv` joins six selected call sites to their ranges and landings. Action values are retained without interpreting their complete chains. Previous writes, helper side effects, dynamic bindings and rollback on any of these paths are not proved.

### Historical #94 cross-check

The old packet is bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its original outer FDE is `0x32725d0..0x3272b3a`, its call at `0x3272785` uses relative slot `0x57755a8`, and that slot names FDE `0x3273810..0x327396c`; the Location is `0x56dfbf8`, `state.rs:107:37`, and the selected comparison uses 2. The optional check independently authenticates that artifact and validates those bytes, slot, Location and FDE records.

The separately authenticated #115 context instead has Location `0x64767a8`, `state.rs:123:37`, referenced at `0x3c1352f`, followed by a comparison of `rax` with 1 at `0x3c1353b`. Similar source suffixes and topology are navigation clues, not evidence of equal layouts, tags, helper semantics or addresses between releases. Neither the old nor the #115 loader call is re-owned here.

## Implementation and comparison

Independent Rust reconstruction: **not yet implemented**. Cargo graph, lockfile, compiler/linker flags, two-build comparison, source-byte comparison, helper closure, vtable/relocation/data closure, runtime fixtures and whole-ELF equivalence are not yet implemented or measured. The explicitly stated within-target sorter mask is the only normalization used; raw original windows are retained. The Python models in the focused tests operate on synthetic trees, rows and rings and never execute target instructions.

## Results and limitations

`summary.json` reports 2 cursor FDEs totaling 1,384 bytes, 9 additional FDEs totaling 4,521 bytes, 32 cursor partitions, 46 cursor transfers, 49 other selected branch transfers, 73 additional byte windows, 38 contextual windows, 32 unrolled descent steps, 22 LSDA rows and 10 selected call-to-range joins. These are selected records, not coverage denominators. The focused suite passed 39 tests with zero skips, including authentic and recomputed-digest corruption, FDE, opcode, branch, dynamic-symbol, relocation, LSDA, out-of-range, overlap and NOBITS controls. It also checked 9,646 synthetic sorted-ring cases, all 3,280 key sequences of length 0 through 7 over three keys, reverse walks crossing the 7/8/9 depth boundaries, and negative controls for invalid descriptor state and nonadjacent duplicates. Synthetic outcomes are not captured node behavior.

No `abci` progress gate is requested. The requested full begin/action/end-block path and all state-root inputs remain incomplete. Runtime object identity, source-key meaning, ordering invariants of all producers, the large sorter and its tie stability, complete cleanup/action chains, external delivery, snapshot compatibility and actual state-root bytes remain open. Next question: trace the producer of the shared 20-byte lookup key and prove the post-conversion representation and alias conditions before connecting these rows to a specific root input or external consumer.
