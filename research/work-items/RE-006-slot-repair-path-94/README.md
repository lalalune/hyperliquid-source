# RE-006: cancellation slot-index removal and upward repair on node 94

A cancellation can remove a slab index from the user's `+0x20` set, and the selected deletion path searches unsigned keys, repairs underfull nodes with a left-sibling preference, and can propagate merges to a contracted root; these rules make the index transition reconstructible beyond a single leaf.

- Component ID: `orderbook`, task `RE-006`.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not implementation evidence; no reference code was copied.
- Claim status: addresses, bytes, FDE extents, relocation records, selected branch targets and encoded constants are observations. The set's role in the book and the synthetic tree operations are inferences. Target execution and full rollback semantics remain unresolved.
- Scope included and excluded: one search/removal entry, its predecessor cursor, leaf and ancestor repair, merge and both redistribution helpers. The previously studied cancellation body is bounded call-site context only. Other book indexes, caller bodies, allocator and panic internals, concurrency, and a full insert/cancel/match implementation are excluded.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3. GNU objdump 2.42 was used only to inspect the chosen instructions; the generator and tests use standard-library Python plus `tools/elf_index.py` and `tools/fde_extents.py`. They invoke no external program and never execute the captured binary. The collector first checks the input digest, then rejects unbacked mappings, changed unwind extents, body hashes, selected witnesses, edges and diagnostics.

```sh
python3 tools/artifacts.py verify
python3 tools/book_slot_remove94.py --out research/work-items/RE-006-slot-repair-path-94
python3 -m unittest tests.test_book_slot_remove94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-slot-repair-path-94 && sha256sum -c MANIFEST.sha256)
```

For a reproducibility check, substitute a writable relative directory for `<tmp-dir>` and use an environment whose `PATH` contains Python but no binutils:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_slot_remove94.py --out '<tmp-dir>/a'
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_slot_remove94.py --out '<tmp-dir>/b'
diff -r '<tmp-dir>/a' '<tmp-dir>/b'
diff -r -x README.md -x MANIFEST.sha256 '<tmp-dir>/a' research/work-items/RE-006-slot-repair-path-94
```

`evidence.json`, `repair-cases.json` and `decisions.tsv` are the complete generated output. Their hashes and the README hash are in the manifest. Output paths, time zones and hash seeds are not written into these files.

## Evidence

All addresses are linked ELF virtual addresses, not runtime-rebased addresses. Ends are exclusive; `evidence.json` gives file offsets, raw bodies and hashes. The six FDEs total 4,269 bytes. An unwind extent is not, by itself, proof of an original source-function boundary. The collector validates each FDE against the unwind index and checks its full body hash; selected instruction windows and edges then support the specific interpretations below.

| Role in the bounded path | FDE extent |
| --- | --- |
| Search and delete entry | `0x4943a10..0x4943b21` |
| Leaf/internal-key cursor | `0x42afe70..0x42b0055` |
| Leaf deletion and ancestor repair | `0x429db10..0x429e114` |
| Merge | `0x4281080..0x42813b0` |
| Borrow from left | `0x4273a70..0x4273c8e` |
| Borrow from right | `0x427a730..0x427a995` |

The previously studied cancellation path saves a qword at `0x42f7d88` and supplies that value to the slab-removal call; `0x42f827f..0x42f8293` passes a pointer advanced by `0x20` and the address of the saved qword to the selected set entry. The caller tests its return at `0x42f82a2`; false branches to `0x42f84b9`, bypassing intervening tracker work. The interpretation that this is the removed slab index and that the enclosing value is a per-user state uses the prior `RE-006-user-book-cancel-94` and `RE-006-price-level-lifecycle-94` packets. The saved-word link assumes intervening callees do not alter that stack slot through an alias; this packet does not prove their memory effects.

The selected FDEs read a tree root at `+0x00`, height at `+0x08`, and item count at `+0x10`. A node has a parent pointer at `+0x00`, u64 keys beginning at `+0x08`, a u16 parent-edge index at `+0x60`, a u16 key count at `+0x62`, and child pointers beginning at `+0x68`. These offsets are not a recovered Rust ABI. The node-capacity comparison uses an exclusive limit of 12; the inferred maximum is 11 keys.

### Search, delete and first repair

| Condition | Selected byte-backed behavior |
| --- | --- |
| Root is null, or search exhausts a height-zero node | Return false; no call into the cursor and no tree-count decrement on these paths. |
| Search finds a key | Call the cursor, decrement the header count, then return true, subject to root-shrink checks. |
| Match in a leaf | Remove that key by shifting the following keys and decrementing the u16 node count. |
| Match in an internal node | Enter the child preceding the key, follow rightmost edges to a leaf, remove a predecessor, and exchange a key with the position returned by the cursor. |
| Leaf count after deletion is greater than 4, or the leaf has no parent | Skip the initial sibling repair. |
| Underfull leaf has a left sibling | Select it even if a right sibling is available. |
| Underfull leaf is the first child | Select the right sibling; a parent with no separator reaches a failure arm. |
| Remaining keys plus sibling keys plus separator are below 12 | Merge and decrement the parent count. |
| The same sum is at least 12 | Borrow one key through the parent, from the selected side. |

The first leaf check compares the *old* leaf count plus the sibling count with 12. This is the same total as the new leaf count plus sibling count plus the separator. For a five-key leaf, sibling counts 6 and 7 lie on opposite sides of the merge boundary. The evidence records both comparisons and both helper calls; it does not treat an arbitrary byte-pattern hit as an instruction boundary.

### Propagating the repair

After a merge, the caller examines the parent. A parent with more than four keys stops the upward repair; with at most four keys it continues toward the root. At an ancestor, the code again chooses the left sibling if its parent-edge index is nonzero; otherwise it selects the right. The comparison uses `current + sibling + 1` against 12. A merge shifts the separator, keys and child edges, fixes moved children's parent pointers and edge indexes, decrements the old parent, and can continue upward. When merging cannot fit, the corresponding redistribution helper receives `5 - current_count` and returns to the caller.

This is a short human-readable excerpt from the bounded objdump inspection; the generator checks the underlying bytes and never consumes this rendering:

```text
429dd9c: cmp edx,0xc
429dd9f: jae 0x429e0ae
429e0ae: mov esi,0x5
429e0b3: sub rsi,rax
429e0be: call 0x4273a70
```

A root-shrink flag is set only on the selected path when the visited root has no keys. The entry requires a non-null root and nonzero height, replaces the root with its first child, lowers the height, clears the new root's parent pointer, and passes the old root with size `0xc8` to an indirect routine. The repair code also supplies sizes `0x68` and `0xc8` on different node-release paths. These call arguments support inferred leaf/internal allocation shapes; allocator semantics are not proved here.

### Failure ordering and external edges

The following are selected local guards, not an exhaustive malformed-state or unwind analysis:

| Guard | Failure destination | Ordering visible in the selected bytes |
| --- | --- | --- |
| First or upward repair needs a separator in an empty parent | `0x429e0fb` | The initial leaf shift and count decrement precede this path. |
| Merge edge index exceeds its checked bound, or merged count reaches 12 | `0x4281365`, `0x428137e` | These checks precede the merge's node-count store. |
| Left or right redistribution exceeds capacity, or donor subtraction borrows | `0x4273c43`, `0x4273c5c`, `0x427a963`, `0x427a97c` | Both checks precede the corresponding count stores. |
| Redistribution child-level consistency fails | `0x4273ba9`, `0x427a8cf` | Count and key operations occur before this failure. |
| Upward child-copy lengths disagree | `0x429e0e2` | Parent-key movement and parent-count decrement precede the check. |
| Root-shrink flag with null root or zero height | `0x4943afb`, `0x4943b08` | The entry's tree-count decrement precedes these checks. |

No atomicity or rollback guarantee follows from these observations. Twelve diagnostic sites bind to target relocation-backed source locations whose retained suffix is `src/collections/btree/node.rs`. The source-location strings identify diagnostics, not original node function names.

`evidence.json` records 41 fixed byte windows, 38 selected conditional branches, nine direct call sites including the caller context, 33 RIP-relative indirect call sites, and one register call with its preceding slot load. The slot relocations identify the imported names `memcpy` and `memmove`; the other relative relocation addends are recorded without assigning unproved helper semantics. These selected lists are not a complete CFG or relocation census.

### Inferences and synthetic controls

The cancellation context and earlier book evidence support identifying the set key as a slab index. The six selected FDEs themselves expose a generic u64-keyed tree; neither an original source symbol nor exclusive order-book ownership is established.

`repair-cases.json` contains 15 synthetic tree projections: misses, leaf deletion, left/right boundary merges and borrows, internal predecessor replacement, multi-level merges, both directions of upward borrow, a retained root and three-level contraction. Each records initial and final trees and model events. `decisions.tsv` covers 120 combinations of underfull count, sibling count and side; some combinations are deliberately noncanonical and do not assert reachable target states. These examples are independently authored models of the pinned instructions, not observations from a running or emulated node.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Target-to-Rust raw and normalized comparisons, masks, two-build results, and helper/data/vtable/relocation closure: not yet measured. No bytes are transplanted into an implementation. The full target bodies are retained as evidence only.

The focused suite passed 13 unittest methods with zero skips in a Python-only executable path. Controls reject an incorrect target digest, altered FDE extent or body, every selected witness, conditional opcode and displacement, direct and selected indirect call displacement, a changed relocation, altered diagnostic instructions/text/location/path, and invalid or NOBITS addresses. Synthetic tests check both sides of the boundary, the 15 recorded fixtures and 107 sequential deletions against an independently maintained set, with repeated deletion as a negative control. These checks validate the collector and the model's consistency, not the target's runtime behavior.

## Results and limitations

Two independent generations with distinct hash seeds and time zones were byte-identical and matched the retained three generated files. Artifact digest/signature verification and catalogue consistency passed. Repository-wide test discovery was not run under the stated memory constraint.

This is one selected slot-index removal path, not all RE-006 order-book transitions. The list of branches is curated, the error path after a failure call is unresolved, and the synthetic model does not establish live-state validity or execution equivalence. Other insertion and cancellation indexes, runtime reachability, indirect helper behavior and full transaction effects remain open. No component completion gate is requested.

Next question: establish how the caller maintains the saved slot key and tracker state across a successful or failed deletion, including the indirect helpers and any unwind side effects.
