# RE-006: reduce-only queue filtering in a third node #94 insertion variant

This packet establishes that a previously unmeasured insertion variant rebuilds an order-ID queue by silently dropping stale IDs, recording live IDs whose position cannot support their slot side, and retaining the remaining IDs in their original order; this gives a reconstruction the variant's actual queue-filter boundary and its allocation and failure behavior.

- Component ID: `orderbook` (RE-006, book transitions).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: independent repository base `966865f1637a29ce75b019e1bf11d5529cc6f519`; `can1357-hl` reference pin `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference supplies search terms only and is not implementation evidence.
- Claim status: the bytes, operands, FDE records, selected direct branches and relocations are observations. The names `order ID`, `position`, `side` and `reduce-only` are inferences from the surrounding existing book research, as distinguished below. No function has been executed.
- Scope included and excluded: the complete two FDE byte ranges for the queue rebuild and its predicate, including their failure and cleanup blocks. The known insertion caller is an entry edge only. The separately researched position accessor, allocator and growth routines, subsequent resizing and cancellation, all other insertion paths, and full book correctness are excluded.

## Reproduce

Run from the repository root. The generator reads the authenticated ELF and uses only Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. It parses FDEs, file-backed executable sections, fixed instruction encodings and ELF64 RELA entries. It does not invoke a disassembler or run the target.

```sh
python3 tools/artifacts.py verify
python3 tools/reduce_queue_filter94.py --out work/reduce-queue-check
python3 -m unittest tests.test_reduce_queue_filter94
diff -r work/reduce-queue-check research/work-items/RE-006-reduce-queue-filter-94 -x README.md -x MANIFEST.sha256
python3 tools/catalogue.py --check
```

For a reproducibility check, generate into two empty, distinct directories with different `PYTHONHASHSEED` and `TZ` values and compare their contents. `MANIFEST.sha256` records all packet-local file hashes. Recorded environment: Python 3.12.3, Linux x86-64. GNU objdump 2.42 was used only for manual reading of these bounded FDEs; its output is not an input or a generated evidence file. No target execution, networking, chain access, or credentials are involved.

## Evidence

All addresses are linked ELF virtual addresses. For these `.text` ranges the file offset is VA minus `0x1000`. FDEs identify unwind-described ranges, not necessarily source-function boundaries. `functions.tsv` supplies exact extents, FDE addresses, file offsets, lengths and whole-range hashes; `windows.tsv` partitions both ranges into eight consecutive, hash-checked raw byte windows. The manual instruction review is limited to these two ranges and the single caller edge. It is not a whole-program call census.

| Descriptive role | FDE range, half-open | Extent | FDE VA |
| --- | --- | ---: | --- |
| Queue rebuild | `0x24c47f0..0x24c4a64` | 628 bytes | `0x10beb64` |
| Slot and position predicate | `0x2775400..0x27755d5` | 469 bytes | `0xd84004` |

The previously researched insertion body has a direct call at `0x26ee927` to the rebuild. The rebuild calls the predicate at `0x24c484a`, `0x24c488f`, `0x24c496c` and `0x24c49ac`. `calls.tsv` decodes their actual rel32 operands. The caller body itself is outside this packet. The predicate calls an external lookup at `0x36f57f0`; its body and meaning are not established here. `indirect.tsv` separately records four RIP-relative call slots and their `R_X86_64_RELATIVE` addends; addends are not treated as evidence that the called implementations have been recovered.

### Predicate and three-way disposition

The input is a qword key. The predicate first checks an ID table, using multiplier `0xf1357aea2e62a9c5`, 64-bit rotate-left 20, the high seven bits as a fingerprint, and 16-byte control groups. Its key entries are addressed at a 16-byte stride. A successful lookup supplies a slab index. The exact instruction witnesses and immediate fields are in `fields.tsv`; `branches.tsv` contains the selected taken destinations and raw opcodes.

| Observed condition | Predicate result | Auxiliary vector |
| --- | ---: | --- |
| Table empty, key absent, index at or past slab length, or slot tag equals 2 | 0 | no append |
| Live slot; external lookup returns no tree root, or search misses the key | 0 | append the input key |
| Live slot; signed qword in the found entry is zero | 0 | append the input key |
| Live slot; signed qword is nonzero and `(qword > 0)` equals the byte at slot `+0xc2` | 1 | no append |
| Live slot; signed qword is nonzero and the two bytes differ | 0 | append the input key |

The equality is byte equality, not simply a test of the low bit of the slot byte. The branch sequence at `0x2775594..0x27755a3` tests zero before comparing the signed-positive flag to the slot byte. A slot byte outside `{0, 1}` cannot equal that flag. This describes the code for such a byte, without claiming that a valid node state permits it.

The slab's backing pointer is at `+0x08`, its length is at `+0x10`, slots have stride `0xf8`, and a 32-bit slot tag equal to `2` is treated as vacant. The position-shaped tree's node count is a 16-bit field at `+0x322`; its child pointers start at `+0x328`. The key compare uses `+0x2d0` with an index initially `-1`; the value address uses a `0x40` increment followed by a `-0x30` displacement. Thus the first key is at `+0x2c8` and its qword value is at `+0x10`; subsequent keys and values advance by 8 and `0x40` bytes respectively. These are memory-layout observations, not a recovered Rust type. The lookup receives a copied 20-byte value and an object pointer adjusted by `0xf8`; its result's `+0x08` is the tree root and `+0x10` controls descent.

### Queue construction and failure paths

The rebuild receives two consecutive input spans. Each span is visited in order, advancing its cursor before the predicate call. Predicate result zero continues scanning. When no key survives either span, it returns a four-qword header with capacity `0`, pointer value `8`, head `0`, and length `0`; this pointer is an empty-buffer representation, not a dereferenceable allocation.

On the first result of one, it requests `0x20` bytes, stores that key, and initializes capacity `4` and length `1`. It copies the remaining iterator state, filters both remaining spans, and appends each later result of one. A full output buffer calls the separate growth routine before continuing. The final header has head `0`, the allocated pointer and the accumulated length. Consequently the survivor list preserves input order and duplicate keys; it performs no deduplication. Keys that take the predicate's append arm go to a different vector, whose capacity is checked and whose growth is an external call. The predicate itself does not cancel an order.

A null result from the first allocation reaches the failure-handler call at `0x24c4a34`. The FDE also contains a cleanup path which releases a nonempty allocated output buffer and resumes unwinding. The predicate may already have appended rejected keys before that allocation is attempted; these two functions do not demonstrate rollback. The exact behavior of the failure handler and the rejected vector's growth helper is outside the selected ranges.

### Inferences and comparison with prior work

The qword key is identified as an order ID, the `+0xc2` byte as an order side, and the searched signed value as a position using the independently reviewed `RE-006-perp-order-insert-94` packet and this call edge. That packet describes a comparable filter for two other insertion bodies and expressly did not run the third body. The present packet ties the previously unmeasured third variant to its own two FDEs and recovers the concrete queue construction and failure arms. Similarity of the rules does not make the machine-code bodies identical, and no normalization or binary-equivalence comparison is made.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build flags, Cargo lock, two-build comparison, raw and normalized Rust comparisons, relocation closure, allocator contracts, external position lookup, and target fixture execution are **not yet measured**. No captured binary, lifted code, emulator, or network is run. The small fixture table in the unit tests is an illustrative model of the statically read conditions; it is not a target oracle or a differential test.

The 9 unit-test methods check both FDE extents, all eight window hashes with three one-byte corruptions per window, 34 branch targets with opcode and displacement corruption controls, extracted instruction immediates, selected rel32 calls, four relative relocation records, digest rejection, malformed FDE/relocation records, missing or NOBITS mappings, and illustrative signed-boundary and two-span ordering cases. They have no skips and do not invoke external programs.

## Results and limitations

The generated `summary.json` reports 2 FDEs, 8 raw windows, 34 selected branch records, 8 direct-call records, 4 indirect-call records and 22 immediate records. These are evidence counts, not function coverage or execution counts. The complete byte ranges are retained, but the branch table is selected rather than an automatic instruction or CFG census.

The inputs are assumed to satisfy the hash table and tree invariants; malformed in-memory structures, indirect callbacks and allocation failures have not been executed. The later consumer of the auxiliary vector, its cancellation reasons, quantity resizing, position updates, and the entry conditions of the surrounding insertion body are not resolved here. There is no independently built implementation or full insert/cancel/match acceptance claim, and no component progress gate is requested.

Next question: trace the auxiliary vector from this specific insertion variant to its later consumer and prove when a recorded ID becomes a cancellation, including the invalidation and failure branches.
