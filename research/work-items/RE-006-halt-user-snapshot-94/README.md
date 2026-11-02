# RE-006: user-state snapshot before a halt cancellation sweep

Node 94 copies the user-state tree, including each user's queue and both nested trees, before a halt sweep cancels users from the original book, then drains that snapshot; a reconstruction can preserve the pre-cancellation user enumeration and the observed copy, failure and cleanup order.

- Component ID: `orderbook`, task `RE-006`.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base `e5c9b6436876b2a4a39daef813171f9879317699`; reference `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a search lead only; no code was copied.
- Claim status: machine bytes, FDE extents, selected calls, branches and operands are observations. Book ownership, field names and data-structure roles rely on the prior packets identified below. Runtime behavior beyond the stated static conditions and source-level boundaries remain unresolved.
- Scope included and excluded: five selected copy FDEs, three selected value-drop and draining-iterator FDEs, their selected calls, branches, fields and failure/cleanup arms, and twelve bounded windows in previously studied callers and the outer drop routine. The earlier sweep, cancellation and outer-drop FDEs, allocator internals and all other releases are not selected. This is a partial cancellation path, not complete RE-006 acceptance.

## Reproduce

Run from the repository root with Python 3 and the authenticated artifacts. The author used Python 3.12.3 and GNU objdump 2.42 on Linux x86-64; objdump was used only for manual instruction-boundary review, and its rendering is not an input or an evidence file. The generator imports the repository's ELF and FDE readers, verifies the full digest first, excludes `SHT_NOBITS` from file-byte mappings and calls no external program. It reads the executable as data and never executes it. Network, signing, keys and chain state are not used.

```sh
python3 tools/artifacts.py verify
python3 tools/halt_user_snapshot94.py --out work/halt-user-snapshot-a
python3 -m unittest tests.test_halt_user_snapshot94
python3 tools/catalogue.py --check
diff -r -x README.md -x MANIFEST.sha256 work/halt-user-snapshot-a research/work-items/RE-006-halt-user-snapshot-94
```

To check deterministic regeneration with different hash seeds and timezones:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/halt_user_snapshot94.py --out work/halt-user-snapshot-a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/halt_user_snapshot94.py --out work/halt-user-snapshot-b
diff -r work/halt-user-snapshot-a work/halt-user-snapshot-b
```

`MANIFEST.sha256` covers every other file in this directory. `functions.tsv` includes complete unmasked bytes and hashes of the selected extents. `context.tsv` contains the caller windows, `witnesses.tsv` selected body windows, `branches.tsv` selected conditional destinations, `calls.tsv` selected direct calls, `indirect.tsv` selected RIP-relative slots and their relative relocation addends, and `fields.tsv` operands extracted from pinned encodings. `lsda.tsv` decodes the selected FDEs' exception call-site tables, retaining the raw header and row bytes; it does not decode the action tables. These are selected records, not an automatic instruction or call-graph census. `summary.json` reports their counts and target digest.

## Evidence

All addresses are linked ELF virtual addresses before load bias; intervals are half open. The selected bytes are in `.text`, whose file offset for these windows is virtual address minus `0x1000`. An FDE gives an unwind-described extent, not by itself a source-level function boundary. The selected entrypoints are also connected by the actual direct calls in `calls.tsv`.

| Selected role | FDE extent | Bytes |
| --- | --- | ---: |
| Outer user-tree copy | `0x49a1a00..0x49a1f40` | 1344 |
| Per-user value copy | `0x496c1a0..0x496c2bf` | 287 |
| Qword deque copy | `0x458fba0..0x45903d5` | 2101 |
| Nested key-tree copy | `0x497b9b0..0x497bcb5` | 773 |
| Nested value-tree copy | `0x498a7f0..0x498b1e6` | 2550 |
| Per-user value drop | `0x49082e0..0x490840c` | 300 |
| Nested value-tree draining iterator | `0x494ecc0..0x494f06d` | 941 |
| Outer user-tree draining iterator | `0x494e170..0x494e531` | 961 |

### From halt to the snapshot and cancellation

The existing `RE-006-halt-book-sweep-94` packet identifies the two book sweeps as stubs on the halt path. The `RE-006-user-book-cancel-94` packet connects their reason-`0xc` calls to user-wide cancellation. Those caller and cancellation FDEs are not selected here. The new copy path, with bounded caller context, is:

```text
book sweep A / B
  book +0xc8 == 0: skip copy and cancel loop
  book +0xc8 != 0, book +0xb8 == 0: take failure call
  otherwise: copy(book +0xb8 root, book +0xc0 height)
    0x49a1a00: recursively copy outer user tree
      0x496c1a0: copy each 0x50-byte value
        0x497b9b0: copy nested key tree when its length is nonzero
        0x458fba0: copy the qword deque
        0x498a7f0: copy nested value tree when its length is nonzero
  iterate copied keys; pass each 20-byte key and the original book to
    prior user-wide cancellation with flag 1 and reason 0xc
  drop the copied tree
```

The copy calls are at `0x43078a1` and `0x4307ea1`; the cancellation calls are at `0x4307aac` and `0x43080ac`. In the second sweep, the copied root and computed count are loaded after the copy at `0x4307ea6`, and the walk uses the copied node's count, parent and child fields before copying a key at `0x4308077`. The original book is passed to cancellation at `0x4308093`. A corresponding result and cancellation window is retained for the first sweep. The clone finishes before the first selected cancellation call; a copy failure therefore precedes that call on this path. Allocation, cleanup and failure-handler side effects are not proven atomic.

A zero book count bypasses the root check. A nonzero count with a null root takes the failure edge before copying. For a nonnull root the copy receives the root and height, not the original book count. The returned traversal count is assembled from copied node counts; a reconstruction should not silently substitute the original count in malformed states. The precise behavior of arbitrary inconsistent or cyclic trees is not established.

### Outer tree and value ownership

The earlier `RE-006-prune-book-user-states-94` and `RE-006-user-book-cancel-94` packets identify the `+0xb8` structure as the user map and identify its value fields. The machine offsets in this packet independently match that layout:

| Object or node | Offset or size | Observed use |
| --- | --- | --- |
| Book | `+0xb8`, `+0xc0`, `+0xc8` | outer root, height and count gate in the caller |
| Outer node | `+0x00`, stride `0x50` | each value is passed to the separate value-copy FDE |
| Outer node | `+0x370`, `+0x378`, `+0x454`, `+0x456`, `+0x458` | parent, 20-byte keys, parent edge index, 16-bit count, children |
| Outer node allocations | leaf `0x458`; internal `0x4b8` | allocation sizes passed on the respective paths |
| Nested key tree | keys `+0x08`, count `+0x62`, parent index `+0x60`, children `+0x68` | qword keys and links; leaf/internal allocation `0x68`/`0xc8` |
| Nested value tree | keys `+0x08`, values `+0x60`, stride `0xb8`, count `+0x84a`, parent index `+0x848`, children `+0x850` | qword keys and independently constructed values; leaf/internal allocation `0x850`/`0x8b0` |

The outer function first descends through the first child for nonzero height, constructs a new internal node, then for each source entry copies its 20-byte key, calls the value copier, recursively copies the next child, writes the copied fields and repairs the child's parent and edge index. On height zero it allocates a leaf and copies keys and values. The copied count is accumulated as entries and descendants are installed. The three selected tree-copy functions compare destination node count to `0xb` before adding an entry; `10` passes this guard and `11` takes the selected failure branch. These are unsigned comparisons at the observed insertion points, not a claim that malformed trees are supported.

The `0x50`-byte value is assembled in this order:

| Value field | Observed copy decision |
| --- | --- |
| `+0x20` root, `+0x28` height, `+0x30` count | If count is zero, the result has null root and zero count. Otherwise a null root takes the failure call; a nonnull root and height go to `0x497b9b0`. |
| `+0x00` deque | `0x458fba0` reads length at `+0x18` and head at `+0x10`, allocates for qword items and handles wrapped segments before constructing a new header. |
| `+0x38` root, `+0x40` height, `+0x48` count | If count is zero, the result has null root and zero count. Otherwise a null root takes the failure call; a nonnull root and height go to `0x498a7f0`. |

For the zero-count tree arms the instructions explicitly initialize the result root and count. They do not establish a meaningful empty-tree height value; the packet does not infer one. A zero count suppresses traversal even if the source root is nonnull. This is a different local gate from a root-null test and matters when comparing malformed or stale in-memory representations.

The nested value-tree copy also obtains the per-value qword-vector length and pointer from value offsets `+0x40` and `+0x38`, allocates `length * 8` bytes when nonempty, and calls through the copy slot before installing the copied value. The offset calculation is visible in `fields.tsv`: the source cursor starts at node `+0x111`, uses signed displacements `-0x71` and `-0x79`, and the value starts at node `+0x60`. Those bytes establish independent allocation on the nonempty path; the product meaning of that vector is not established here.

### Failure and boundary ordering

| Condition | Selected observation |
| --- | --- |
| Outer book count nonzero, root null | Caller takes its failure call before the outer copy. |
| Value nested-tree count nonzero, root null | Value copier takes its corresponding failure call before calling that nested copier. |
| Child copy expected for a nonzero height returns null | The respective recursive copy reaches a failure call. |
| Leaf/internal allocation returns null | The relevant allocation failure arm is selected; its exact allocator contract is outside scope. |
| Destination node count is at least `0xb` at insertion | The selected guard reaches a failure arm before that node's increment/store. Earlier copied nodes may already exist. |
| Qword deque length requires more than `0x7ffffffffffffff8` bytes | The checked size path takes the failure slot before the corresponding allocation. The largest length passing this arithmetic check is `0x0fffffffffffffff`; this is a derived arithmetic bound, not an allocation-success guarantee. |
| The deque copy unwinds | Its call-site row selects `0x496c284`, which jumps to the temporary key-tree drop and unwind-resume path. |
| The nested value-tree copy or its missing-root failure call unwinds | Their call-site rows select `0x496c289`, which conditionally passes the temporary deque buffer to the release slot, drops the temporary key tree and resumes unwinding. |
| An outer internal-node value copy unwinds | Its row selects `0x49a1ea2`; the path calls the partial-construction helper `0x4901620` and resumes unwinding. A leaf-node value-copy unwind selects `0x49a1e9d` and also calls that helper. |
| An outer recursive child copy unwinds after its value copy | Its row selects `0x49a1ea7`; the path drops the just-copied temporary user value, then calls `0x4901620` and resumes unwinding. |
| The key-tree drop in the per-user value drop unwinds | Its call-site row selects `0x49083d7`, which conditionally passes the deque buffer to the release slot, calls the nested value-tree drop and resumes unwinding. |

### Snapshot cleanup

After the selected cancellation loop, each sweep calls the previously studied outer drop routine `0x49ad040`. It calls the newly selected outer draining iterator `0x494e170` to obtain entries and passes each `0x50`-byte value to `0x49082e0`. That value drop first calls `0x49a9fb0` on value `+0x20`; when the deque capacity at value `+0x00` is nonzero it passes the pointer at `+0x08` and eight times that capacity to the release slot. It then sets up the nested value-tree iterator using root `+0x38`, height `+0x40` and count `+0x48` when the root is nonnull. Each returned node and index selects a `0xb8`-byte value at node `+0x60`; when its capacity at value `+0x30` is nonzero, the pointer at value `+0x38` and eight times the capacity go through the same release slot. This loop ends when the iterator returns a null node.

The selected nested draining iterator also passes node pointers to the release slot, choosing `0x850` or `0x8b0` bytes according to the observed height-dependent branch; the outer draining iterator likewise walks and releases its own nodes. In the value-drop unwind arm, the deque is conditionally released and `0x49a9ab0` is called on value `+0x38` before control resumes unwinding. The outer copy's cleanup arms also call the value-drop FDE. These observations show individual cleanup edges and ordering, but do not prove that every partially copied state is rolled back: the invoked nested-tree drop routines, allocator and all possible unwind paths are not closed here.

The selected FDEs point into `.gcc_except_table`. Their retained call-site rows use omitted LPStart, ULEB call-site fields and, for the paths above, action zero. Interpreting the lookup position as the call's return address minus one places the deque-copy call at `0x496c1eb` in the row for `0x496c284`, and the nested value-tree copy at `0x496c209` and its null-root failure call at `0x496c27c` in rows for `0x496c289`. Similarly, the value-drop key-tree call at `0x49082f0` selects `0x49083d7`. The outer internal value-copy, recursive child-copy and leaf value-copy calls are at `0x49a1b0e`, `0x49a1b28` and `0x49a1d34`, respectively. The row bytes, interval endpoints and landing-pad addresses are reproduced by `lsda.tsv`; neither the personality implementation nor nonzero action chains are decoded. The exact behavior of helper `0x4901620` remains outside this packet. The tests verify these selected row-to-call associations and reject corrupt headers and intervals.

The slots in `indirect.tsv` include relocation addends when an `R_X86_64_RELATIVE` entry is present. An empty addend field means this collector found no such entry; it does not resolve another relocation type or prove a callee's semantics. Names such as allocation, release and copy are inferred from their calling patterns and existing evidence, not from executing the binary.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Target ABI, build flags, two-build comparison, source-to-target raw or normalized matches, helper closure, complete relocation closure and whole-ELF identity are not yet measured. No mask or binary-equivalence denominator is claimed. No target code, emulator, or captured node is run.

Thirteen targeted unittest methods passed without skips and with binutils absent from `PATH`. They verify the pinned digest and all eight FDE body hashes; corrupt three positions in each selected body; corrupt every context window, selected conditional displacement and direct/indirect call encoding, and every extracted operand; reject malformed FDE and LSDA metadata, changed selected relocation addends, unmapped addresses and NOBITS addresses; and exercise the selected `0xb` node guard and deque-size arithmetic boundaries. They regenerate and compare all generated files. The arithmetic checks are synthetic checks of the static interpretation, not observations from running a target or a substitute for full transition fixtures.

## Results and limitations

The generated summary records 8 FDEs, 12 caller-context windows, 29 selected body witnesses, 86 selected conditional branches, 37 direct calls, 28 indirect call sites, 52 encoded operands and 64 call-site rows from 8 exception tables. These are evidence-record counts, not function coverage or an exhaustive CFG. The retained FDE bytes include the selected failure and cleanup code, but the nested callbacks, allocator and actual unwind effects are not closed.

The user-cancellation bodies and the exact chain of order-level removals are prior evidence, not re-executed here. The source tree is trusted only as a lead. This packet does not prove that the halt is reachable in a particular block, that every malformed tree terminates, that all allocation failures roll back, or that the reconstructed Rust or whole node matches the target. No component progress gate is requested.

Next question: close the invoked nested-tree cleanup, nonzero action chains and allocator contracts to establish which allocations survive each failure during partial construction.
