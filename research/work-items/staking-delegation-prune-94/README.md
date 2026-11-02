# staking: deletion and repair of the two delegation books in node #94

Node #94 removes emptied user and validator delegation-book rows through two different 20-byte-key tree layouts, but both use predecessor replacement, the same five-row minimum and eleven-row capacity, upward merge or borrowing, and a continuation cursor plus a root-empty flag; these details allow a reconstruction to preserve traversal while the books shrink.

- Component ID: `staking`, staking and validator lifecycle; the bounded question is how empty outer delegation-book entries are removed and their trees repaired during undelegation.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference `l1/staking.rs` is a lead, not copied source or evidence of the binary layout.
- Claim status: byte observations and selected-path interpreter results below; book identities are inferred from the documented caller and state layout. Untested paths and the limits of the interpreter are explicit below.
- Scope included and excluded: eight FDE-described ranges in `functions.tsv`: two remove-at-cursor entries, two leaf-removal and repair routines, and four directional transfer routines. The two incoming call instructions are linkage witnesses only; their enclosing functions, economic balance changes, destruction of owned nested maps, allocator implementation, panic unwinding, and root replacement by the enclosing caller are outside the scope. This is not an implementation of undelegation or a component gate.

## Reproduce

From the repository root with Python 3.12.3 and the authenticated artifact:

```sh
python3 tools/staking_delegation_prune94.py --out research/work-items/staking-delegation-prune-94
python3 -m unittest tests.test_staking_delegation_prune94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/staking-delegation-prune-94 && sha256sum -c MANIFEST.sha256)
```

The generator uses only the Python standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. It checks the full input digest before parsing. It starts no external program and does not execute the captured node. It emits the eleven generated files beside this README. Its x86 decoder and interpreter are adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`; the fixture construction, independent tree checks, pins, control cases and evidence tables here are new. File-backed section selection excludes `SHT_NOBITS`.

For a separate deterministic regeneration, choose two empty output directories and run:

```sh
PYTHONHASHSEED=17 TZ=UTC python3 tools/staking_delegation_prune94.py --out work/prune-a
PYTHONHASHSEED=811 TZ=Pacific/Honolulu python3 tools/staking_delegation_prune94.py --out work/prune-b
diff -r work/prune-a work/prune-b
```

The output contains no time, hash seed, timezone, machine path, or disassembler text. For human inspection only, GNU objdump 2.42 was used on individual ranges; it is not a generator or test dependency. For example:

```sh
objdump -d -M intel --start-address=0x2fcdc10 --stop-address=0x2fcdd80 artifacts/node/94/hl-node
```

## Evidence

Coordinates in the tables are ELF virtual addresses; file offsets are separate columns. `functions.tsv` gets its half-open extents from actual FDE records, not adjacent unwind starts. An FDE is an unwind range, not proof of a complete source function or of all executable functions. `instructions.tsv` retains the decoded instruction bytes and direct targets; `branches.tsv` records each conditional's two destinations and the numbers of deletion and direct-transfer fixture cases reaching each edge, in separate columns. Linear decoding and the 35 fixed byte witnesses are independently checked against the authenticated image. `calls.tsv` separates direct calls, slots and register-indirect calls; it is not an exhaustive whole-ELF caller census.

The caller sites `0x33acc3b` and `0x33ace81` directly call `0x2fd7a50` and `0x2fdb2f0` respectively (`anchors.tsv`). The former is reached from removal of an empty user-to-delegations row; the latter from removal of an empty validator-to-state row, as established in `research/work-items/staking-stake-accounting-94`. That prior packet ran real tree helpers as dependencies and tested book-level behavior, but did not name or map these eight helper addresses or their repair decisions. This packet isolates the deletion subpath and its cursor and repair contract. The prior tool's broad execution is not counted again as a newly recovered implementation.

### The two node layouts

Both layouts use 20-byte keys. The user-book and validator-book labels are inference from the two caller paths and the prior serializer-backed state map. Offsets below are observed from the selected code; the removed value is treated as opaque bytes here.

| Property | User book | Validator book |
| --- | ---: | ---: |
| Cursor entry | `0x2fd7a50` | `0x2fdb2f0` |
| Leaf/repair | `0x2fc3270` | `0x2fcdc10` |
| Borrow from left / right | `0x2fa1d00` / `0x2fa76c0` | `0x2fa20c0` / `0x2faab60` |
| Value array and stride | `+0x8`, 24 bytes | `+0`, 32 bytes |
| Key array and stride | `+0x110`, 20 bytes | `+0x168`, 20 bytes |
| Parent pointer / edge index | `+0`, `+0x1ec` | `+0x160`, `+0x244` |
| Occupied count / child array | `+0x1ee`, `+0x1f0` | `+0x246`, `+0x248` |
| Deallocated leaf / inner size | `0x1f0` / `0x250` | `0x248` / `0x2a8` |

Parent edge index and occupied count are 16-bit. In the evaluated fixtures every reachable child is checked against its parent pointer and edge index after the operation. The sizes are the arguments at the deallocation boundary, whose allocator is hooked, not a recovered allocator ABI.

### Removal and continuation

The cursor input is a node pointer, height, and slot index. With height zero, the entry calls the leaf helper directly. With nonzero height, it descends into the child before the selected separator, follows rightmost children to a leaf, removes that leaf's last entry, and exchanges the predecessor into the original internal slot. The returned key and value are the originally selected row, not the predecessor. The result also contains a node/height/index continuation gap. Our checker follows that gap and its parent links to the next in-order key, or the end.

Leaf removal copies out the key and value, shifts the suffix of each array left, and decrements the count. The stale last slot is not cleared on this path. The 132 single-root-leaf cases cover every removal position for lengths one through eleven in both layouts and compare the complete node bytes to a separately constructed compaction projection, including the stale suffix.

### Repair decisions

The following table describes the selected normal paths. `n` is the occupied leaf length before deletion; `s` is the selected sibling length. The pre-deletion comparison is why the threshold is 12 even though a node holds at most 11 rows.

| Condition after the row is removed | Action in the selected path |
| --- | --- |
| New length at least 5 | Return without sibling repair. |
| Underfull but no parent | Return; no sibling is consulted. |
| Underfull, parent edge index nonzero | Select the left sibling. |
| Underfull, parent edge index zero | Select the right sibling; an empty parent enters a panic path. |
| `n + s < 12` | Merge the two nodes and parent separator; release the discarded node. |
| `n + s >= 12` | Move one separator through the parent using the directional helper. |
| Parent becomes underfull | Repeat at the next level, transferring `5 - current_count` rows when borrowing. |
| An internal root becomes empty | Write byte 1 through the supplied flag pointer; the caller must handle the root. |

The merge and borrow paths also move internal child edges and update their parent and edge-index fields. Both directions were exercised after a leaf merge caused an internal-level underflow (`deep_borrow` rows in `cases.tsv`). Separately, `transfers.tsv` contains 720 direct helper cases with valid synthetic leaf or internal siblings, transfer amounts 1 through 5, and every source/destination occupancy that remains in the 5 through 11 range. Each case checks all sorted rows, sibling counts, parent and child links, and absence of deallocation. These direct bulk calls are helper contracts; reachability of every amount through a staking action is not established. Height-three fixtures exercise cascading merges and the empty-root flag. The flag does not itself replace or free the old root in these selected helpers; no claim about the caller's root promotion is made. `flags.tsv` covers 24 tests of input flag bytes 0, 1, 2 and 255: the empty-internal-root path writes 1 and the other tested paths preserve the incoming byte. The latter two byte values are noncanonical corruption controls, not evidence of reachable flags.

The directional helpers reject a destination whose existing count plus the requested transfer reaches 12, and reject transfer counts greater than the donor's count. Eight deliberately corrupt descriptors cover both guards in both directions and both layouts; each reaches the specific captured panic branch before the test's node bytes change (`corruption.tsv`). These are corruption controls, not claims that malformed internal descriptors can arise from valid staking actions.

### Cases and controls

`cases.tsv` records 2,212 synthetic cases: 132 single leaves, 1,666 two-child cases spanning every combination of sibling lengths 5 through 11 and every leaf slot plus the internal separator, 22 multilevel cases, and 392 height-two cases spanning all internal sibling occupancies 5 through 11 at outer and interior leaf positions. Every case compares all live in-order keys and opaque values, the removed row, the continuation successor, the root-empty flag, deallocation count, occupancy bounds, and parent/edge links against independent expectations. For each layout the multi-level cases include both internal borrow directions, a root replacement candidate and up to three successive merges. The small synthetic values are fixtures, not captured user state.

`mutations.tsv` contains 20 single-byte changes to occupancy limits, predecessor selection, cursor adjustment, free size and moved-child indices. Each unmodified case succeeds before its changed case is checked; all 20 changes are detected by a mismatch, a fixture invariant, or the targeted panic hook. Unit tests also independently corrupt all 35 anchors, reject a wrong input hash and non-file-backed/out-of-range reads, and test the eight explicit panic guards. Mutation results are tests of this harness and selected inputs, not an exhaustive mutant census.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo scope and lockfile, compiler and linker flags, reproducible builds, raw or normalized native-code comparisons, call-target closure, relocation/data/vtable closure and whole-ELF comparison: **not yet implemented or measured**. No normalization mask is applied to the recorded bytes.

The interpreter reads instruction bytes from the authenticated image and operates on synthetic memory; it does not start the executable. It runs the eight selected bodies for the reached paths. The copy/move and free operations are modelled at their external boundaries; panic sinks stop the run, and exceptional unwinding is not followed. The input B-tree values are byte carriers, not fully initialized nested Rust maps, so neither ownership cleanup nor the economic operation is exercised. Prior economic semantics and the upper calls are context, not retested here.

## Results and limitations

- Selected denominator: 8 FDE ranges, 11,615 bytes and 2,313 linearly decoded rows. Of those rows, 1,949 were reached by the 2,212 normal fixture cases. Of 158 conditional instructions, both outgoing edges were seen for 63 in deletion cases; direct-transfer fixtures saw both outcomes for 24 conditional instructions. Unreached instructions and one-sided branches remain visible in `instructions.tsv` and `branches.tsv`; the counts do not establish component or whole-node coverage.
- All 2,212 cases matched their independent checks; all eight deliberately corrupt transfer descriptors reached their expected failure branch; all 20 targeted byte mutations were detected; all 24 flag controls matched; all 720 direct-transfer cases preserved the expected rows, counts and links. These are static interpretation results, not captured node execution.
- Both normal and corrupt cases stop at modelled external boundaries. Allocator semantics, panic/unwind paths, arbitrary heights and layouts, missing FDEs, raw callers not listed here, lower-level inner delegation removal and the caller's final root handling remain open.
- The work is for #94 only. Stake accounting and epoch transitions across #94 and #115 are a larger acceptance scope; no progress gate is requested.

Next question: can an independently authored implementation preserve these cursor and child-link invariants while removing nested delegation rows, including ownership cleanup and the caller's root replacement?
