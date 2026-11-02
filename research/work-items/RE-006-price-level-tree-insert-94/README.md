# RE-006: price-level entry insertion and split propagation on node 94

This packet establishes how a resting order's price-level entry is returned or inserted and how an 11-key price-level node splits and propagates to a new root, giving the order-book reconstruction the node layout, split boundaries, parent-edge repairs and failure edges needed for this part of insertion.

- Component ID: `orderbook`, task RE-006.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference labels are leads, not source authority; no reference code was copied.
- Claim status: byte observations and their limited inferences are separated below. The synthetic cases illustrate the inferred rules; they are not target executions.
- Scope included and excluded: two previously unpinned FDE ranges in price-level entry insertion, their connection to the established order-insert path, selected branch and indirect-call sites, split cases and failure diagnostics. The already documented order-insert and price search bodies are context only. Price selection, FIFO linking, order allocation, complete trading transitions, allocator internals and dynamic behavior are outside this packet.

## Reproduce

From the repository root, with Python 3.12.3 on Linux x86-64:

```sh
python3 tools/artifacts.py verify
python3 tools/price_level_tree_insert94.py --out work/price-level-tree-check
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-006-price-level-tree-insert-94 work/price-level-tree-check
python3 -m unittest tests.test_price_level_tree_insert94
python3 tools/catalogue.py --check
```

The collector first checks the full node digest, uses `tools/elf_index.py` and `tools/fde_extents.py` for section and FDE interpretation, and reads bytes and ELF relocations directly. It does not run a binary or invoke a disassembler. `MANIFEST.sha256` records the output and README hashes. The two function hashes and their complete raw bytes are in `evidence.json`. The collector's fixed instruction-site inventory is not an automatic proof that every instruction or control-flow path was discovered.

## Evidence

Addresses are linked ELF virtual addresses, not rebased runtime addresses. For these `.text` bytes the corresponding file offset is VA minus `0x1000`; every row also records its file offset. FDE ends are exclusive unwind ranges and are not, on their own, proof of original source function boundaries.

| New range | FDE | File offset | Bytes | Raw SHA-256 |
| --- | --- | --- | ---: | --- |
| Entry handling | `0x4956990..0x4956ae0` | `0x4955990` | 336 | `fd358c2aa6b17f1afdd3dd3bcb3109bd8dc00fd29f1a13043ddc10d238608265` |
| Node insertion and propagation | `0x4239fc0..0x423ad0a` | `0x4238fc0` | 3,402 | `cc9fa9a76bb9f87badfb502e760efea60480069815b5e42cfa015985487f3f5e` |

The already documented order-insert call site `0x4312d9c` reaches `0x45a3890`, which is the price-level search/entry context. Three direct calls from that context reach `0x4956990`: `0x45a3922`, `0x45a3941`, and `0x45a396a`. The new entry code calls `0x4239fc0` at `0x4956a00` for an absent entry in an existing tree. A separate caller at `0x493ec29` also calls that helper; its owning component is unresolved, so the helper is not claimed to be book-exclusive. `calls.tsv` contains the encoded `E8` instructions and decoded destinations. This packet does not reanalyse those existing caller functions; the order-book interpretation comes from their previously documented placement in `RE-006-perp-order-insert-94` and `RE-006-price-level-lifecycle-94`.

### Entry and node layout

The following are observations from fixed instruction witnesses. Offsets are relative to the node or tree pointer used by these routines; the descriptions of the enclosing objects are inferences from the call context.

| Field | Observed access |
| --- | --- |
| Node `+0x00` | Values in 32-byte slots; the entry result is node plus `index * 0x20`. |
| Node `+0x160` | Parent pointer, set to zero on a new leaf and repaired on moved children. |
| Node `+0x168` | Eight-byte keys indexed with stride 8. |
| Node `+0x1c0` | Two-byte parent-edge index, rewritten when child edges move. |
| Node `+0x1c2` | Two-byte live key count; the capacity comparison uses 11. |
| Internal node `+0x1c8` | Eight-byte child pointers; at most 12 accompany 11 keys. |
| Tree `+0x00`, `+0x08`, `+0x10` | Root pointer, height and entry count on the new-root and entry paths. |

A node without children is allocated with size `0x1c8`; an internal sibling or new root uses `0x228`. These are allocation sizes, not a claim about a Rust `repr(C)` type. `witnesses.tsv` retains the precise bytes for these accesses, allocations and stores. The allocation slot has a relative relocation; the slots used for byte copies and overlapping shifts name `memcpy` and `memmove` respectively in the dynamic symbol table (`imports.tsv`). This identifies those external edges without asserting allocator behavior.

At `0x4956998` the first entry word is compared to zero. The zero arm returns the existing value address and does not increment the tree count. The nonzero arm prepares a new 32-byte value with qword stores of zero at offsets 0 and `0x10`; no claim is made about the other bytes. With no root it allocates a leaf, writes parent and count zero, installs that root with height zero, inserts the key and value, and increments tree `+0x10`. With an existing node it calls the insert/propagate helper, increments the same count after return and returns the selected value address. The entry representation's relationship to a zero key is unresolved; the available insertion-path evidence does not establish which keys can reach this routine.

### Insertion into a full node

For a live node with fewer than 11 keys and an insertion index in `0..=length`, the helper inserts at the index. If the index is below the length it shifts the key and 32-byte value suffixes; an append bypasses the shifts. `nonfull-cases.tsv` enumerates the 66 valid `(length, index)` combinations for lengths 0 through 10 as abstract examples, including empty and append cases. Those rows are a model derived from the selected bytes, not observed node executions.

For a full 11-key node, the branches at `0x423a024`, `0x423a113` and `0x423a119` select the old key to promote and the destination for the new key. The parent split at `0x423a4e0..0x423a680` uses the corresponding thresholds. The resulting cases are:

| Insertion index | Old pivot index | New key goes to | Left keys after insertion | Right keys after insertion |
| ---: | ---: | --- | ---: | ---: |
| 0..4 | 4 | left, same index | 5 | 6 |
| 5 | 5 | left, index 5 | 6 | 5 |
| 6 | 5 | right, index 0 | 5 | 6 |
| 7..11 | 6 | right, index minus 7 | 6 | 5 |

The split copies the old keys and 32-byte values after the pivot to the new sibling and writes the shortened count to the old node. It then inserts the new pair on the selected side. On an internal split, the copied child range has one more pointer than the copied key count; moved children receive the new parent pointer and their edge index. A promoted pair is inserted into the parent with the new right-child pointer; a full parent repeats the split, and an absent parent takes the new-root path. The new root gets the former root and new sibling as children and raises the recorded tree height by one. The 12 full-node examples in `split-cases.tsv` and 12 edge-conservation examples in `parent-split-cases.tsv` use synthetic keys and child numbers. They check this interpretation's ordering and conservation, not the target's runtime results.

### Failure and control edges

`branches.tsv` records 46 manually identified conditional sites with raw bytes and taken destinations; it is a fixed-site record, not an independently decoded instruction census. `imports.tsv` records 31 selected RIP-relative call or pointer-load sites and their relocation types, symbols where present, and addends. `locations.tsv` decodes nine relative Location relocations. Embedded build-path prefixes are not reproduced; the recorded suffix and hash preserve their identity.

| Condition | Taken destination | Observation |
| --- | --- | --- |
| Initial leaf allocation returns zero | `0x4956ab7` | allocation failure helper, size `0x1c8`, alignment 8 |
| Initial leaf index at least 11 | `0x4956ac7` | capacity assertion |
| Leaf sibling allocation returns zero | `0x423ac4e` | allocation failure helper, size `0x1c8` |
| Internal sibling or new-root allocation returns zero | `0x423ac0a`, `0x423ac6b` | allocation failure helper, size `0x228` |
| Split copy range or child range exceeds its checked bound | `0x423ac35`, `0x423abd2`, `0x423abee` | bounds failure helper; key and child limits are separately passed |
| Parent height or copied edge lengths disagree | `0x423abb9`, `0x423ac1a` | assertion text is retained in `evidence.json` |
| Root is absent during promotion, height increment wraps, root height disagrees, or new root exceeds capacity | `0x423ac5e`, `0x423ac7d`, `0x423ac8c`, `0x423aca5` | distinct failure sites |

The code also compares a split-result word to 2 before parent propagation. On the no-split path it explicitly writes 2; after a split the compared word comes from the promoted value. The admissible range of that word in every live book state is not established here. Unwind cleanup includes deallocation calls and a resume edge; rollback and observable failure effects were not evaluated.

### Inferences and unresolved questions

- The node is a price-level B-tree node, and the 32-byte value is the level's pair of head/tail options, because the established order-insert path passes the side-selected price tree and uses the returned level. The two new FDEs alone do not name their owning component or original Rust functions.
- Zero stores at the two option-tag positions support an initially empty level. They do not establish values of the payload bytes or a target ABI for a new Rust implementation.
- Valid insertion indices and node lengths are assumed in the abstract case tables. Out-of-range test inputs check the model and collector; they do not assert how the target behaves on corrupted state.
- The embedded diagnostics name standard allocation-library B-tree files. Their presence supports the data-structure interpretation but does not prove source identity, compiler version, a full CFG, or behavior of the allocator and failure helpers.

## Implementation and comparison

Rust implementation: not yet implemented. No compiler flags, Cargo lock, two-build result, target equivalence, normalization masks, helper closure or dynamic comparison is claimed. The 90 synthetic rows in the three case tables are explanatory models; they do not execute target instructions. Tests include changed target bytes and digest, changed instruction and branch bytes, invalid or NOBITS mappings, missing relocation, split boundary cases and independent key/edge conservation checks.

## Results and limitations

The static packet contains 2 FDE ranges (3,738 bytes), 36 fixed byte witnesses, 46 conditional sites, 6 direct-call sites, 31 selected indirect sites, 9 location records and 90 abstract cases. The focused unittest suite passed 11 tests with no skips. The table counts describe this selected evidence, not all order-book functions or a whole-node denominator. No RE-006 progress gate is requested. The analysis has not demonstrated complete CFG coverage, real allocator or panic behavior, target execution, caller input invariants, rollback, or Rust binary equivalence.

Next question: establish the valid first-word and key invariants of every price-level value reaching the promoted-value tag check, including the transitions that empty and remove a level.
