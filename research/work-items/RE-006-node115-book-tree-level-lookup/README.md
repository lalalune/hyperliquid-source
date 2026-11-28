# RE-006: tree-represented book level lookup before order unlink

- Component: order-book removal, issue #3915; target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: upstream `2da45cb0a761cff6b478e40421699857d87a94df`.
- Addresses are ELF virtual addresses. The enclosing FDE is `0x58e1400..0x58e1f34`.
- This is an independently inspected static path; no captured code is executed or emulated. No component gate is claimed.

## Question and incremental scope

The existing `RE-006-node115-book-level-removal` packet traces the flat-representation lookup and calls out tree selection as unproved. On the same caller, how does the tree branch find the level pointer passed to the existing unlink routine? This packet covers that tree branch, the hit-to-call handoff, and the two null-result exits. It does not repeat the existing analysis of flat lookup, order unlink, or subsequent empty-level removal.

## Evidence and interpretation

The earlier packet derives a saved signed search key from the order price and side, then distinguishes representations using the overflow flag from negating the map's first word. At `0x58e15be` the non-overflow branch goes to flat handling; the fallthrough reads the tree root from map `+8` and the height at `+0x10`. A null root reaches `0x58e1a60`, which zeros `r12`; the unlink call later receives that null pointer as its seventh argument.

For a non-null root, the code reads a 16-bit count at node `+0x5e2` and compares the signed key against qwords in the node, beginning at `+0x588` and advancing by eight bytes. It uses signed less/greater condition codes, continues to the next key only when the search key compares greater, and branches on equality to `0x58e1a1d`. A miss decrements the remaining height; borrow branches directly to the unlink handoff with the already-zero `r12`. Otherwise it loads the next child from `node+0x5e8+8*index` and repeats. This interpretation assumes a valid tree and nonnegative height, and does not establish behavior on malformed node pointers or counts.

On equality, `r8` has been decremented by `0x80` once per compared key. The instructions `sub rcx,r8; add rcx,-0x80` compute `node+0x80*index`; `r12` receives that address. It is passed to `0x518e690`, whose effects are not established here, and then stored at `[rsp]` immediately before the call to unlink `0x58dfbc0`. The existing flat-path packet identifies the matching caller argument as the level pointer; this packet does not assert that the 128-byte stride is a complete native type definition or prove the helper's behavior.

`records.json` retains both selected windows, decoded from the FDE start to avoid mistaking interior bytes for instruction boundaries. Forty-seven individually checked instruction facts include the branch destinations, comparison instructions, field displacements, pointer arithmetic and call handoff. Fourteen in-memory instruction mutations are rejected by those facts with the digest comparison deliberately bypassed for the mutation check. The facts and controls establish selected instruction properties, not runtime semantics or full CFG coverage; semantic descriptions above are static dataflow interpretations.

## Reproduction

Run in the repository root using Python 3.11 and Capstone 5.0.6, with the pinned ELF present:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-tree-level-lookup/verify.py
(cd research/work-items/RE-006-node115-book-tree-level-lookup && shasum -a 256 -c MANIFEST.sha256)
```

The verifier reuses the upstream MIT-authored ELF/FDE support from `RE-001-node115-registry-row-labels` and the verification structure of `RE-006-node115-book-level-removal`. `offline-log.json` is the actual verifier output. No binary execution or live networking is required.

## Limitations and next question

The two selected windows do not prove all paths through the 2,868-byte caller. The tree's construction, key uniqueness and node invariants, opaque helper behavior, error and unwind paths, other callers, post-unlink deletion of tree-represented empty levels, and end-to-end cancellation remain unresolved. Next, connect the tree-represented empty-level deletion branch to the same saved map and key, and independently establish the helper's effect.
