# RE-006: top-order clone on node #94

- Component ID: `orderbook` (task RE-006, book transitions)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (labels used as leads only, nothing copied)
- Claim status: observation for every offset, branch, constant and count below; inference where the section says so; unresolved items are listed at the end
- Scope included and excluded: included are `0x49e3930`, its only caller `0x4a06f70`, the slab slot clone map, and the reachability of both. Excluded are the two self-check bodies beyond their entry gate, and how levels and slots are written.

## Reproduce

Run from the repository root. The tool starts no external program and never runs the binary. It takes about 10 s.
Author environment: Python 3.12.3, Linux x86-64. It reads only `artifacts/node/94/hl-node`, and uses the repository's
`tools/elf_index.py` and `tools/fde_extents.py` for section and FDE parsing.

```sh
python3 tools/artifacts.py verify
python3 tools/top_order_clone.py --out work/top-order-check
diff -r work/top-order-check research/work-items/RE-006-top-order-clone-94 -x README.md -x MANIFEST.sha256
python3 -m unittest tests.test_top_order_clone
```

Generated files: `functions.tsv`, `callers.tsv`, `slot_clone_map.tsv`, `mutations.tsv`, `evidence.json`. Every number there
comes from `struct` reads of the ELF or from the evaluator in the tool.

## Evidence

Coordinates are virtual addresses. Offsets marked `+` are from the named structure's start. Analysis was complete for the
two functions in `functions.tsv`: each was decoded to its exact FDE end.

### Path

```text
0x4a06f70 (out, book)
  0x49e3930 (stack record, book, edx = 0)   tree at book +0x98
  0x49e3930 (stack record, book, edx = 1)   tree at book +0x80
  copy both records out, 0x1f0 bytes, return out
0x49e3930 (out, book, edx)
  edx (low 32 bits) nonzero: tree at book +0x80, else book +0x98
  no root, or tree length 0:                panic l1/src/book/book/mod.rs:1043:83
  first leaf, climbing if that leaf is empty
  level byte at value +0x00 is 0:           panic l1/src/book/book/mod.rs:1044:58
  slab index at value +0x08 past the slab, or slot tag equal to 2:
                                            panic l1/src/book/book/mod.rs:1044:68
  clone the 0xf8-byte slot into out
```

### Tree and level layout read here

| Field | Offset |
| --- | --- |
| Tree header | root `+0x00`, height `+0x08`, length `+0x10` |
| Node values | `+0x00`, stride 0x20: level byte `+0x00`, slab index `+0x08` |
| Node parent, parent index, length | `+0x160`, `+0x1c0`, `+0x1c2` |
| Node edges | `+0x1c8` |
| Book slab | entries `+0x08`, length `+0x10`, slot stride 0xf8 |

The descent is the height in steps through edge 0, in the usual remainder loop and eight-step loop. A first leaf with length
0 makes the walk climb until a parent index is below that parent's length. A climb past the root panics at
`library/alloc/src/collections/btree/navigate.rs:534:47`.

### Slot clone map

`slot_clone_map.tsv` covers all 0xf8 bytes. Every source byte differs from its neighbours in the cases, so a wrong offset
changes the result.

- Copied unchanged: `+0x00` to `+0x4f`, `+0x60`, `+0x90` to `+0xb0`, `+0xc2`, `+0xc8` to `+0xf5`.
- `+0x50`, `+0x58`, `+0x60` is a vector of 8-byte elements with its elements in a new buffer. The new capacity equals the
  length, so the source capacity is not read. Length 0 gives pointer 8 and no allocation.
- `+0x68` is a tag read as 32 bits and written as 64 bits: 1 if the low 32 bits equal 1, else 0. Its 0x20-byte payload at
  `+0x70` is copied only for 1.
- `+0xb1` is a tag: 1 if the byte equals 1, else 0. Its 0x10-byte payload at `+0xb2` is copied only for 1.
- With a tag absent, the payload bytes in the record are the function's own uninitialized stack, not source bytes.
- `+0xc3` to `+0xc7` and `+0xf6`, `+0xf7` are never written.

Vector size checks: a length of `1 << 60` or more calls the allocation error at GOT slot `0x576dfb8` with align 0, and a failed
allocation calls it with align 8. Lengths `0x0fffffffffffffff`, `1 << 60` and `1 << 61` are in the cases.

The vacant check here compares all 64 bits of `+0x00` with 2. A tag of `0x100000002` is not vacant here.

### Who calls it

| Function | Direct sites | Caller | Argument at the site |
| --- | --- | --- | --- |
| `0x49e3930` | 2 | `0x4a06f70` | `edx` 0, then 1 |
| `0x4a06f70` | 2 | `0x42fc790`, `0x42fd530` | none |
| `0x42fc790` | 2 | `0x4d1c1c0`, `0x4d1dff0` | `esi` 0 |
| `0x42fd530` | 2 | `0x4d1c1c0`, `0x4d1dff0` | `esi` 0 |

None of the four addresses is taken by a rip-relative `lea` or a relocation (`evidence.json`). Both self-checks start with
`test esi,esi` and a `je` to their epilogue (`self_check_gates` in `evidence.json`), and their only direct sites write
`xor esi,esi` first. **So no direct path in #94 reaches this clone.**

### Inferences

- This is the debug data of a crossed-book report. The pair is built inside a self-check that is compiled in and switched
  off at every site. The arm's other contents were not read.
- The two trees are the sides of the book. Bytes here do not say which is the bid side.
- The level value is an optional slab index, stored as a byte and a u64.
- The 64-bit vacant compare and the 32-bit one in the book's collectors agree as long as the upper half of `+0x00` is 0.
  This packet does not show that it always is.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison here is the original bytes against a specification written from the claim above. `spec()` predicts every
output byte, the child elements, the allocation size, and the panic or allocation error. `run()` also checks that the slab
did not change, that nothing was written past the record, and that a non-empty vector points at a fresh allocation of the
right size. Real bytes run for both functions. Stubs replace only `malloc`, `memcpy`, the panic entry and the allocation error.
Stubs poison volatile registers and all xmm registers, and callee-saved registers are checked on exit.

Controls: every condition was inverted and bit 0 of every immediate flipped, one at a time, in both functions, against all
cases. Separate tests change the side offset, the level stride, the slot stride, the vacant constant, one field displacement
and the second flag, corrupt the gate, corrupt the digest, and pass a NOBITS address.

| Point | Reference lead (`l1/book/book/mod.rs`) | Bytes |
| --- | --- | --- |
| Empty side | `top_order` returns `None` | panic at line 1043 |
| Level head | `order_by_oid(level.first?)`, an oid lookup | a slab index used directly, with no hash lookup |
| Missing slot | `None` | panic at line 1044 |
| Use | `TopOrders` for callers in general | one caller pair behind a gate that is 0 at every site |

The reference file has 728 lines and the binary's Location lines are 1043 and 1044, so its numbering is not the source's.

## Results and limitations

| Metric | Value |
| --- | --- |
| Clone cases | 345, 0 mismatches |
| Outcomes | allocation error, align 0: 7, allocation error, align 8: 2, panic 0x5733f50: 14, panic 0x5736298: 81, panic 0x57362b0: 32, panic 0x57362c8: 75, record: 134 |
| Pair cases | 5, 0 mismatches |
| Instructions stepped | 32,339 |
| Mutants killed / survived / unreached | 47 / 4 / 2 |

The 4 survivors were examined one by one, and each has its reason in `mutations.tsv`. All are equivalent:

| Row | Flip | Why it changes nothing |
| --- | --- | --- |
| `0x49e39a5` | `cmp rcx,8` to 9 | `rcx` has nonzero low 3 bits here, so it is never 8 |
| `0x49e3a6e` | `shr rax,0x3d` to `0x3c` | the limit test already rejects bit 60 (test enumerates the top four bits) |
| `0x49e3a75` | bit 0 of `0x7ffffffffffffff8` | the compared byte count is a multiple of 8 |
| `0x4a06fb3` | first copy size 0xf8 to 0xf9 | the second copy overwrites the extra byte |

The 2 unreached rows, `0x4a06fff` and `0x4a07006`, are in the pair's unwind cleanup. No stub unwinds.

No progress gate is requested. Limits:

- A call through a table of pointers built at run time would not appear in the census, so "no direct path" is exact only for
  `E8`/`E9` sites, rip-relative `lea` and relocation addends.
- Only the entry of each self-check was read. That the arm holding the pair call runs only for a crossed book was not shown.
- `malloc`, `memcpy` and the panic entry are contracts.
- The move widths give the sizes in `slot_clone_map.tsv`. Adjacent copied fields may be one Rust field, so the map shows copy
  units, not a struct definition.
- Field names for the slot and the meaning of both tags are unresolved here.

Next question: which side is `+0x80`, read from a site that uses a side constant with a known price order?
