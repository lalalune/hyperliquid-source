# RE-006: how does node #94 attach, detach and cascade order relations?

- Component ID: `orderbook` (task RE-006, book state transitions).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  `can1357/hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference supplied search terms and the
  labels parent, child and peer. No reference code is used or copied.
- Claim status: observation for bytes, call edges, offsets and evaluated transitions; inference for names and
  roles; unresolved items are listed under Results and limitations.
- Scope included and excluded: 17 FDE-bounded functions that read or write three relation fields of one order
  body: parent, peer and the children vector. Excluded: the removal bodies, matching, event contents, the
  external action path, and every function pinned by the open RE-006 price-level packet. The removal
  functions appear here only as call targets, and their bodies were not evaluated.

## Reproduce

Static and offline, working directory is the repository root. The binary is never executed and no external
program is called. Python 3.12.3 on Linux x86-64, standard library only.

```sh
python3 tools/artifacts.py verify
python3 tools/order_relation_transitions.py --out work/order-relations
diff -r work/order-relations research/work-items/RE-006-order-relation-transitions-94 \
  --exclude README.md --exclude MANIFEST.sha256
python3 -m unittest tests.test_order_relation_transitions
```

The generator takes about 35 seconds. `MANIFEST.sha256` holds input and output hashes for this folder.

## Evidence

Addresses are ELF virtual addresses. In `.text`, file offset = VA - `0x1000`. Boundaries come from
`.eh_frame_hdr` and each FDE, read with `struct`, so FDE ranges are unwind ranges and not symbol boundaries.
Instruction boundaries come from the decoder inside the tool, which must end exactly on each FDE end.

Generated files:

| File | Content |
| --- | --- |
| `functions.tsv` | 17 FDEs with size, instruction count, executed count, branch count, raw and masked SHA-256 |
| `edges.tsv` | Every direct call, tail jump and GOT call decoded in those FDEs |
| `callers.tsv` | Every byte-level `E8`/`E9` hit on the entries, with enclosing FDE and fixed `r9d` pattern |
| `scenarios.tsv` | Runs, mismatches and evaluated steps per family and entry |
| `mutations.tsv` | Result of flipping each conditional branch |
| `evidence.json` | Totals, field offsets, lookup byte pins, GOT slots and one worked cascade |

### Order body fields

The lookup at `0x430d380` returns a pointer P. On the slab arm P is slot + `0x20`. The tool pins the bytes for
stride `0xf8`, vacant discriminant 2, the 20-byte user match and the `add rdx, 0x20` that forms P. A second arm
returns a value from a B-tree with stride `0xb8`. `0x43075d0` has the same 656 bytes apart from 2 bytes of one
GOT displacement (offsets 239 and 240).

| P offset | Width | Observed use |
| --- | --- | --- |
| `+0x10` / `+0x18` | 8 / 8 | Option tag and key, parent |
| `+0x20` / `+0x28` | 8 / 8 | Option tag and key, peer |
| `+0x30` / `+0x38` / `+0x40` | 8 / 8 / 8 | Vec capacity, pointer and length of child keys |

### Functions and observed transitions

Each row was confirmed by running the function's own bytes. See "Implementation and comparison".

| Entry | Inferred role | Observed transition |
| --- | --- | --- |
| `0x43032b0` | attach children | Appends each input key to the parent's vector unless already listed, then writes parent = Some(key) on every input child that resolves. The second loop also runs when the parent does not resolve. Frees the input vector. |
| `0x42fbb50` | detach children | Clones the vector, then zeroes the parent tag of each child that resolves. The stale key and the vector itself stay. |
| `0x42fb910` | set peers | Writes peer = Some(other) on each side that resolves, independently. |
| `0x42fbc60` | clear peer | Zeroes this order's peer tag. If the low 32 tag bits were 1, zeroes the tag on the order it pointed to. |
| `0x43073d0` | link relations | Compacts the child list in place to keys that resolve. Input `+0x10` bit 0 attaches this order to the parent at `+0x18`. Input `+0x20` bit 0 sets both peer links only if the key at `+0x28` resolves. Then attaches the kept children. |
| `0x42f7700`, `0x42f7290`, `0x42f7420`, `0x42f7590` | cascade cancel | If the order does not resolve, returns 1. Otherwise clones the vector, recurses on each key in stored order, frees the clone, calls one removal function, returns 0. |
| `0x4303110`, `0x43031e0`, `0x4302f70`, `0x4303040` | cancel children | Loops over a vector it owns, calls the matching cascade with `r9d = 2`, frees the vector. |
| `0x4305340`, `0x43050a0`, `0x43051f0`, `0x4304f50` | cancel peer | Stops if the order does not resolve or the low peer tag byte is 0. Stops if the peer key is in a set passed as root and height. Otherwise clears the peer's link and tail-jumps to the matching cascade with `r9d = 0xb`. |

The worked tree in `evidence.json` is 1 -> (2, 3), 2 -> (4). Its removal order is 4, 2, 3, 1: children first,
depth first, in stored order, with the root last. The clone is taken before recursion, so a key removed earlier
in the walk resolves to nothing and is skipped.

Each cascade pairs with one removal target: `0x42f7700` -> `0x42f7890`, `0x42f7290` -> `0x42f8840`,
`0x42f7420` -> `0x42fa880`, `0x42f7590` -> `0x42f97f0`. Masked hashes give 2 cascade shapes, 2 cancel-children
shapes and 1 cancel-peer shape. All clones passed the same scenarios. The cascade shapes differ in register
allocation, seen by hand in a disassembly that is not part of the generated evidence.

### Callers and reason bytes

`callers.tsv` has 30 hits on the four cascade entries. The fixed `r9d` patterns are 2 (8 sites), `0xa` (4),
`0xb` (4), 7 (2) and 8 (2). The other 10 are `not-fixed`, which includes the 4 recursive calls. This is a byte
pattern scan of the 32 bytes before each site, so `not-fixed` only means that the pattern was not found there.
`0x42fbb50` has 4 hits, one in each removal FDE. `0x43073d0` has 4 hits, 2 each in `0x4d1c1c0` and `0x4d1dff0`.

### Inferences, kept apart from the observations

- Parent, child and peer are reference labels. The bytes support the shapes, one-to-many with a back link and
  reciprocal one-to-one, and do not prove the original names.
- Attached trigger orders and one-cancels-other pairs are the likely product meaning. Nothing here proves it.
- The `r9d` byte reaches the removal call unchanged. Calling it a cancel reason is an inference.
- `0x576dfd8` and `0x576e010` are treated as allocate and free from their use. The slot `0x576dfe0` is `memcpy`
  by its `.rela.dyn` symbol.

### Differences from the reference

These compare observed bytes with unverified reference text at the same commit.

- `book/mod.rs:546` clears a child's parent only when it equals the removed order. `0x42fbb50` has no such compare.
- `book/mod.rs:524` writes one peer direction at insertion. `0x43073d0` writes both directions, and only after
  the peer resolves.
- A search for child recursion found no recursive cancel in `book/mod.rs`. `exchange/handlers/12_modify.rs:140`
  declares `prune_child_tree` as a trait method with no body in the reference tree.

## Implementation and comparison

Rust implementation: not yet implemented. No Cargo.lock, build flags, two-build result or normalized binary
comparison exists for this packet.

The comparison here is between target bytes and a Python specification, not between two builds. A byte-level
evaluator in the tool runs the 17 functions from the ELF. Volatile registers and fresh stack bytes are poisoned,
and callee-saved registers and stack balance are checked on every run. Each run also checks the return value
where one exists, the callee log, the final relation fields and any leaked vector.

Stubs and their assumptions:

- Lookup: returns the body pointer when key and user match, as pinned above. The lookup bodies are not evaluated.
- Removal: logs its arguments and deletes the order. It clears no relation fields, unlike the real function.
- Allocate, free and `memcpy`: conventional behavior. Free also checks pointer and size.
- Vector growth at `0x5774458`: modeled as doubling with a minimum of 4.
- One-time call at `0x576e8b8`: logged only.

## Results and limitations

- 5,932 scenario runs across 17 entries, 0 mismatches, 811,595 evaluated instruction steps.
- 69 conditional branches were flipped, covering the 5 single functions and one clone of each masked shape:
  64 killed, 0 survived, 5 unreached. The unreached 5 are capacity checks in unwind cleanup at `0x430343d`,
  `0x43075ac`, `0x42f756f`, `0x430301c` and `0x43031be`. One scenario per cascade covers allocation failure.
- Coverage by function is in `functions.tsv`. The unexecuted instructions are cleanup and allocation-error arms.
- The other clones were not mutated. Their masked bytes repeat a mutated clone, and all of them ran the baseline
  scenarios.
- Scenarios use acyclic child graphs with at most 10 orders. They are finite samples, not a proof over all states.
- Unresolved: what the set read by the cancel-peer family holds, what the one-time call at `0x577ab98` does,
  the meaning of each `r9d` value, the input layout's source, and whether a child or peer link to an absent
  order can occur in a live book.
- This packet requests no progress gate and changes no catalogue, Makefile or docs file.

Next question: at `0x430f650` and `0x430fd91`, what does the insert path pass as the root and height of the set
read by `0x4305340`?
