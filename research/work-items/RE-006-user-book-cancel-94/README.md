# RE-006: one user-wide book cancel on node #94

- Component ID: `orderbook` (task RE-006, book transitions)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (labels used as leads only, nothing copied)
- Claim status: observation for every offset, branch, constant and count below; inference where the section says so; unresolved items are listed at the end
- Scope included and excluded: included are the path from a user to the list of removal calls, its four wrapper copies, the collectors, the filtered builder `0x4303460`, the four book-walking closures and the census of wrapper callers. Excluded is the removal routine itself and everything behind it: `0x42f7890` and its three siblings are stubs here, and open PR #47 owns `0x42f7890`. Matching and insertion are excluded.

## Reproduce

Run from the repository root. The tool starts no external program and never runs the binary.
The tool takes 70 to 100 s, and `test_static_files_regenerate` runs a reduced pass, not the mutation pass.
Author environment: Python 3.12.3, Linux x86-64. It reads only `artifacts/node/94/hl-node`, and uses the repository's
`tools/elf_index.py` and `tools/fde_extents.py` for section and FDE parsing.

```sh
python3 tools/artifacts.py verify
python3 tools/user_book_cancel.py --out work/user-cancel-check
diff -r work/user-cancel-check research/work-items/RE-006-user-book-cancel-94 -x README.md -x MANIFEST.sha256
python3 -m unittest tests.test_user_book_cancel
```

Generated files: `functions.tsv`, `callers.tsv`, `edges.tsv`, `closures.tsv`, `status_names.tsv`, `mutations.tsv`,
`evidence.json`. Every number there comes from `struct` reads of the ELF or from the evaluator in the tool.
The disassembly excerpt below is for reading only and is not an input to anything.

## Evidence

Coordinates are virtual addresses. Offsets marked `+` are from the named structure's start. Analysis was complete for
the functions in `functions.tsv`: each was decoded to its exact FDE end. `executed` there is how many instructions ran;
the rest are panic arms, unwind cleanup, and tree-walk branches this path never takes.

### Call path

```text
caller, edx = 1
  wrapper 0x4303b30 / 0x43038b0 / 0x4303650 / 0x4303db0
    find the 20-byte user in the map at book +0xb8        (not found: return, no call at all)
    dispatch 0x431db10 / 0x431dc50
      flag byte != 0: chain builder 0x4451540 / 0x4450680 -> collect 0x4886370 / 0x486bd50
      flag byte == 0: filter builder 0x4451e80 / 0x4451ff0 -> collect 0x48713f0
      each builder: sort the u64 keys, then build a set     (0x49273c0, 0x4298270)
    loop over the set in order                              (0x4948f30)
      removal routine (book, key, user, rcx, r8, reason byte)
    drain the set, freeing its nodes
    flag byte != 0: map removal, drop the entry unless the word is the none value
```

| Wrapper | Dispatch | Removal stub | Map removal stub | Entry drop stub | User passed to removal |
| --- | --- | --- | --- | --- | --- |
| a `0x4303b30` | `0x431db10` | `0x42f7890` | `0x4945b50` | `0x4351d30` | stack copy made before each call |
| b `0x43038b0` | `0x431db10` | `0x42f8840` | `0x4945b50` | `0x4351d30` | stack copy made before each call |
| c `0x4303650` | `0x431dc50` | `0x42f97f0` | `0x4942a30` | `0x4351c00` | the pointer it received |
| d `0x4303db0` | `0x431dc50` | `0x42fa880` | `0x4942a30` | `0x4351c00` | the pointer it received |

With rel32 fields and rip-relative displacements zeroed, a equals b and c equals d (`normalized_sha256`), and the two
dispatches, chain builders, filter builders and chain collects match pairwise. Filter collect `0x48713f0`, both tree
`next` functions, the set builder, bulk push and the set `into_iter` step are shared by all four.

### Entry arguments

| Register | Observed use |
| --- | --- |
| `rdi` | book; stride 0xd8 in every caller that indexes books |
| `rsi` | pointer to the 20-byte user |
| `edx` | flag; only its low byte is read |
| `rcx`, `r8` | passed to the removal routine unchanged |
| `r9d` | reason; only its low byte is read, and it reaches the removal routine zero-extended |

### Layouts read here

Book: `+0x08` slab entries, `+0x10` slab length, `+0xb8` root, `+0xc0` height of the user map.

| Tree | Keys | Values | Parent | Parent index | Length | Edges |
| --- | --- | --- | --- | --- | --- | --- |
| user map | `+0x378`, 20 bytes | `+0x00`, stride 0x50 | `+0x370` | `+0x454` | `+0x456` | `+0x458` |
| first tree (entry `+0x20`) | `+0x08`, u64 | none | `+0x00` | `+0x60` | `+0x62` | `+0x68` |
| second tree (entry `+0x38`) | `+0x08`, u64 | `+0x60`, stride 0xb8 | `+0x00` | `+0x848` | `+0x84a` | `+0x850` |

Each tree header is root, height, length, and a missing root means no keys: a stale length beside a null root is ignored.
Slab slot: `+0x00` tag, compared as 32 bits with 2 (vacant); `+0xb0` flag byte; `+0xd8` u64 key.

### What gets collected

1. First tree keys are slab indexes. An index at or past the slab length, or a slot whose low 32 tag bits are 2, is
   skipped without a panic. Otherwise the slot's `+0xd8` value is collected.
2. With flag byte 0, a slot whose `+0xb0` byte is exactly 1 is also skipped, and the second tree is not read.
3. With a nonzero flag byte, `+0xb0` is not read and every second tree key is collected as it stands, with no slab check.
4. The keys are sorted as unsigned u64. Up to 20 keys use an inline insertion sort; 21 or more go to the sort at GOT
   slot `0x5774f50`. Equal keys collapse in the set build.
5. Removals run in ascending key order. The list is fixed first: a stub that destroys the slab and the user map on the
   first removal does not change the later calls.
6. The set's nodes are freed in the drain; every allocation in the path is returned (`leaked` is checked per case).

If a tree's length field exceeds its real size the walk panics at `navigate.rs:534:47` before any removal.

### Map entry

With a nonzero flag byte the wrapper always calls the map removal, even when nothing was collected. It compares 0 with
the first word of the result and skips the drop only on signed overflow, that is, only for `0x8000000000000000`.
`0x4945b50` and `0x4942a30` each load that word in 3 `movabs` instructions (`evidence.json`). The entry's first
field is a vector capacity in the drop at `0x4351d30`, so the word is a capacity niche, and a missing entry is an
expected outcome of this call rather than an error.

### Who calls it

`callers.tsv` lists 26 direct call sites of the four wrappers from `.text` byte patterns. All 26 pass `edx = 1`,
and no wrapper, dispatch or builder has its address taken in a rip-relative `lea` or a relocation (`edges.tsv`).
`0x4451e80` and `0x48713f0` have no other route in a and b, so **the `+0xb0` filter is never reached through any
wrapper**. It is reached through `0x4303460`, the function below.

Reason values at the call sites, with the name that the status serializer's jump table `0x7038dc` gives that value
(`status_names.tsv`, 36 entries read from the arms of `0x4a9a1a0`):

| Reason | Sites | Serializer name at that value | Shape of the caller |
| --- | --- | --- | --- |
| `0x2` | 4 | `canceled` | literal user: all `0xff` or all `0xfe`, in `0x42d2790`, `0x42d3d50`, `0x42e0840`, `0x42e1320` |
| `0xc` | 4 | `delistedCanceled` | walks a tree with the user map's key layout, `+0x378` stride 20 |
| `0xd` | 6 | `liquidatedCanceled` | inside `0x4cf37f0`, `0x4cf94a0`, `0x4d2b3c0`, `0x4d2cd20` |
| `0xe` | 2 | `outcomeSettledCanceled` | walks a list of 20-byte users |
| `0x10` | 2 | `internalCancel` | `0x4d69da0`, `0x4d6a070` |
| register | 8 | not known here | the four closures, from byte `+0x45` of their host record |

### Book-walking closures

`0x4c63f20`, `0x4c64080`, `0x4c641c0` and `0x4c64300` copy the user from host `+0x30`, then read a mode word at `+0x00`.
Mode 1 cancels in one book, any other mode in every book in order. The book index is the host `+0x08` value, reduced
modulo 10000 in `0x4c63f20` and `0x4c64300` only. An index at or past the book count panics at `l1/src/books.rs:19:47`.
A nonzero byte at `+0x44` then makes one more call, with the mode and the `+0x08` value (`closures.tsv`). All four pass
flag 1.

### Filtered builder, `0x4303460`

It takes the book in `rsi` and the user in `rdx`, repeats the user search, and calls the filter builder directly. It
writes tag 2 when the user is absent. Otherwise it writes a set iterator with the keys (tag 1, or tag 0 when no key
survived), the book at `+0x48` and the user at `+0x50`. It removes nothing. Its two callers, `0x4cdd580` and
`0x4cde380`, each call it inside a loop that steps a book pointer by 0xd8.

### Inferences

- The u64 key is the order id: slot `+0xd8` and the second tree's keys are the same kind of value, and the removal
  routine looks its key argument up in entry `+0x38` (`0x42f79a4`). The bytes here only show a u64.
- The first tree holds orders resting in the slab. The second holds orders that have no slab slot, since its keys pass
  no slab check. They may be trigger orders, from the 0xb8 value size; this packet does not read those values.
- `+0xb0` is reduce-only. In the match step `0x431c530` a resting slot with this byte set can fill only when the fill
  reduces its position. The filtered path would then pick every order that is not reduce-only, and it is built once per
  book. Its use is unresolved.
- The reason byte is the order status value. The names fit the callers, and the four jumps at `0x4305055`, `0x43051a5`,
  `0x43052f5` and `0x4305445` set `r9d` to `0xb` (`evidence.json`) on their way to cancel a linked peer, which is
  `siblingFilledCanceled` here. No byte link from the removal routine's stored reason at `0x42f7eb9` to the serializer
  was followed.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison here is the original bytes against a specification written from the claim above. `spec()` predicts every
removal call with all arguments, the map removal, the drop, the first allocation size, whether the external sort ran, a
panic if any, and that nothing leaks. `spec_builder()` and `spec_closure()` do the same for those functions.

Real bytes run for every function in `functions.tsv`. Stubs replace only the removal routine, the map removal, the
entry drop, `RawVec` growth at `0x454f5d0`, the allocator, `memcpy`, `memmove`, `memcmp` and the external sort. Stubs
poison volatile registers and all xmm registers, and callee-saved registers are checked on exit. Trees are real memory
with stale keys past each node length, and heights run to 9 on copy a so the eight-step unrolled descents execute.

Controls: every condition was inverted and bit 0 of every immediate flipped, one at a time, in `0x4303b30`, `0x431db10`,
`0x4451540`, `0x4451e80`, `0x4886370`, `0x48713f0` and all four closures. Each mutant ran on copy a against 354 small
cases, or 16 tall cases when only those reach its row; closure mutants ran against 33 cases. A mutant that spins
stops at a step limit and counts as detected. Separate tests flip the `+0xb0` constant, the vacant constant, the slot stride,
the flag branch, the modulo constant and the book stride, change one literal user byte, corrupt the digest, and pass a NOBITS
address. Copies b, c and d, the other functions in `functions.tsv` and `0x4303460` have no mutation pass; the
normalized hashes above tie b to a and the collect and filter builder of c and d to a, and `spec()` still checks those copies.

The reference file `l1/book/book/mod.rs` differs from the bytes as follows:

| Point | Reference lead | Bytes |
| --- | --- | --- |
| User map value | `BTreeMap<Oid, usize>` | 0x50 bytes: a vector at `+0x00`, a set of slab indexes at `+0x20`, a second tree at `+0x38` |
| Cancel all orders of a user | no such function in this file | this path, in four copies, with removals in ascending key order |

## Results and limitations

| Metric | Value |
| --- | --- |
| Cases per wrapper copy | a 1161, b 820, c 820, d 820 |
| Mismatches, all copies | 0 |
| Instructions stepped | 7,385,204 |
| Filtered builder cases | absent 206, found 451, panic 2, 0 mismatches |
| Closure cases | 480 per closure, 0 mismatches |
| Wrapper call sites | 26, all with flag 1 |
| Mutants killed / survived / unreached | 300 / 0 / 37 |

No mutant survived. These rows stayed unreached, each with its reason in `mutations.tsv`:

| Reason | Rows | What the bytes show |
| --- | --- | --- |
| leaf set up at the loop head | 22 | A second inlined first-leaf descent in each collect, taken at `0x487151c` and its chain collect twin only when the leaf register is null at the loop head. No case took it. Inference: the leaf is already set when the loop starts, so the arm is dead. Not proved. |
| unwind cleanup | 10 | Landing pads. No stub unwinds. |
| allocation failure | 3 | Arms after a failed allocation. The allocator stub never fails. |
| empty vector with capacity | 2 | The free of an empty collected vector at `0x44515cf` and `0x4451f2b`. In every case an empty result came with capacity 0. |

No progress gate is requested. Limits:

- Stubs are contracts. What the removal routine does with its arguments is #47's and later work's subject.
- The two literal users are observed, not explained.
- The vector at entry `+0x00`, the second tree's values and the closures' reason values are unresolved. The drop shows
  only that the vector's elements are 8 bytes and that each second tree value owns another 8-byte vector at `+0x90`.
- Callers were found by `E8`/`E9` byte patterns and rip-relative `lea` scans, then confirmed by decoding back from each
  site to the writes of `edx` and `r9d`. A call through a table of pointers built at run time would not appear.
- Tall trees (heights 8 and 9) ran on copy a only, so the eight-step descents of the c and d collect are matched by
  normalized hash and were not stepped.
- `RawVec` growth and the external sort are contracts, so their capacity choices and stability are not established.
  Neither can change the ascending, deduplicated result.

Next question: which callers of `0x4cdd580` and `0x4cde380` use the filtered path, and does the status written for those
removals equal the `marginCanceled` value 5?
