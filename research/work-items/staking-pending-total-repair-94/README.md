# staking: pending-withdrawal total row removal and tree repair in node 94

This packet resolves the previously stubbed pending-withdrawal total leaf repair: it identifies the layout, merge-versus-borrow boundaries, paired key/value and child-edge transfers, upward repair, and tracked continuation edge needed for an independent reconstruction.

- Component ID: staking (staking and validator lifecycle; withdrawal queue).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference supplied no implementation used here.
- Claim status: observation for fixed machine-code bytes, relative transfers, layout operands and failure literals; inference for the staking field linkage and high-level interpretation; local projections are explicitly not execution of the target.
- Scope included and excluded: four FDE-described code windows below, two call sites into the first window, their direct repair calls, external copy slots, local branch projections and failure sites. The preceding cursor adapter and the outer queue drain were covered or stubbed in `research/work-items/staking-withdrawal-drain-94`; they are context, not reanalysed functions in this packet. Root replacement, other map instantiations, allocator internals, full unwinding and node #115 are excluded.

## Reproduce

Run in the repository root with Python 3.12 and the standard library. The tool authenticates the target before parsing, imports `tools/elf_index.py` and `tools/fde_extents.py`, reads file-backed ELF sections and FDEs, and invokes no external program. The bounded opcode-pattern length decoder is adapted from the MIT-licensed `tools/staking_validator_vote_prune94.py`; unsupported encodings fail closed. It reports direct relative targets and RIP-relative slots from the bytes. No captured binary is executed, and there are no network, key, or chain actions.

```sh
python3 tools/artifacts.py verify
python3 tools/staking_pending_total_repair94.py --out research/work-items/staking-pending-total-repair-94
(cd research/work-items/staking-pending-total-repair-94 && sha256sum -c MANIFEST.sha256)
python3 -m unittest tests.test_staking_pending_total_repair94
```

For the determinism check, replace the placeholders with two distinct writable directories and run from the repository root:

```sh
PYTHONHASHSEED=314159 TZ=UTC python3 tools/staking_pending_total_repair94.py --out <tmp-dir-1>
PYTHONHASHSEED=271828 TZ=Pacific/Honolulu python3 tools/staking_pending_total_repair94.py --out <tmp-dir-2>
diff -r <tmp-dir-1> <tmp-dir-2>
```

The two runs were also made with a PATH containing Python but no binutils. `MANIFEST.sha256` covers this README and every generated evidence file; it does not cover itself. `summary.json` records generated counts, input digest and layout.

## Evidence

Coordinates are ELF virtual addresses. `functions.tsv` gives file offsets, exact FDE extents and SHA-256 for each complete selected window; these are unwind-described extents, not a census of all function boundaries. `instructions.tsv` preserves each decoded instruction's raw bytes; `transfers.tsv` includes all decoded direct and indirect transfers in those windows. Internal relative targets are checked against instruction starts. The decoder does not establish that every row is reachable. `incoming.tsv` checks both direct relative calls into the repair window; their common caller is the previously excluded cursor adapter. `direct-candidates.tsv` records all seven raw `e8 rel32` byte-pattern hits targeting these four windows across `.text`. This scan alone does not prove instruction boundaries or exhaust indirect calls; the two incoming sites and the five in-window sites are anchored to reviewed argument and call byte sequences.

| Window start | FDE end | Purpose in this path |
| --- | --- | --- |
| `0x2fc7e30` | `0x2fc8679` | Remove leaf row, choose first sibling action, repair ancestors and return cursor |
| `0x2fa4900` | `0x2fa4c48` | Move rows and, for internal nodes, edges from left sibling through parent |
| `0x2fa8ed0` | `0x2fa926f` | Move rows and edges from right sibling through parent |
| `0x2fae7a0` | `0x2faebe8` | Merge siblings and separator, remove parent entry and return tracked edge |

The related `research/work-items/staking-validator-vote-prune-94` packet studies a different vote-expiry tree, with 128-byte keys, 112-byte values and different repair windows; its node layout cannot be substituted for this one.

The earlier withdrawal-drain packet identifies the address-keyed `user_to_total_withdrawal` map and explicitly stubs its cursor removal. Its outer path removes a total row when the stored count is at most one. The new call-site and node-layout evidence ties the previously unread leaf repair below that boundary; it does not rerun the outer path or its credit and queue logic.

### Leaf layout and removal

| Field | Node offset / width |
| --- | --- |
| Values | `+0`, 16 bytes per row |
| Parent pointer | `+0xb0`, 8 bytes |
| Keys | `+0xb8`, 20 bytes per row |
| Parent edge index | `+0x194`, u16 |
| Occupied count | `+0x196`, u16 |
| Child edges, internal node | `+0x198`, 8 bytes per edge |
| Allocation size | leaf `0x198`; internal `0x1f8` |
| Maximum occupied entries / nonroot minimum | 11 / 5 |

The leaf routine reads a node and slot from its cursor, saves the selected 20-byte key and 16-byte value, shifts the following portions of both arrays left with `memmove`, and decrements the u16 count. It does not erase the stale last slots. The caller must supply a valid occupied slot: the local fixture validation is not a target-side bounds check. The output carries the removed key and value and a cursor consisting of node, height and edge fields; unused padding is not interpreted.

`register-calls.tsv` binds register-indirect calls to the `memmove` dynamic symbol by checking their defining RIP-relative load and call instruction. The dynamic string/relocation records also identify the direct `memcpy` slots in `transfers.tsv`. No allocator implementation is inferred from an address alone.

### Initial leaf repair

Let `old` be the leaf occupancy before deletion, `sibling` the selected sibling occupancy, and `edge` the leaf's index in its parent. The comparisons and transfer targets are pinned individually in `witnesses.tsv`; `repair-cases.tsv` enumerates the local choices from these opcode conditions.

| Condition, in order | Action |
| --- | --- |
| `old - 1 >= 5` | Return the current cursor; no sibling repair. |
| Underfull and no parent | Return as a root leaf; this branch alone does not remove a root. |
| Parent exists and `edge > 0` | Select the left sibling. |
| Parent exists and `edge == 0` | Select the right sibling; an empty internal parent reaches the failure path. |
| `old + sibling < 12` | Merge the two children with the parent separator. |
| `old + sibling >= 12` | Borrow one row from the chosen sibling. |

The comparison uses the **pre-removal** leaf count. For example, old 5 and sibling 6 merge to 11 occupied rows; old 5 and sibling 7 require borrowing. For a left borrow the continuation slot is incremented by one; the right borrow keeps it. Counts below the normal minimum in the exhaustive table are corruption controls, not claims about valid trees.

A human-readable excerpt, inspected with GNU objdump 2.42, is shown only here; generated files do not parse its output:

```text
2fc7efd: 66 83 f8 04       cmp    ax,0x4
2fc7f01: 0f 87 9c 00 00 00 ja     0x2fc7fa3
2fc7f7f: 41 01 c0          add    r8d,eax
2fc7f82: 41 83 f8 0c       cmp    r8d,0xc
2fc7f86: 0f 83 ac 00 00 00 jae    0x2fc8038
```

### Transfer, continuation and upward repair

A borrow changes the source and destination counts by the requested count. Borrowing left moves the left boundary row into the parent and the previous separator into the destination; borrowing right does the symmetric operation. Both move keys and 16-byte values together. The helpers test destination capacity first and source-count underflow second. A mixed zero/nonzero child-height pair reaches an unreachable-code failure. These checks do not prove equality of two nonzero heights. Count and row writes occur before the child-height failure check, so the evidence does not establish rollback or failure atomicity.

The merge helper removes one parent separator, appends that separator followed by the right node's entries to the left node, moves internal child edges where present, updates child parent pointers and edge indices, and releases the right node. For a tracked edge `i`, the returned edge is `i` for the left side and `old_left_count + 1 + i` for the right side. The low bit of the side byte chooses this rule; other bits are not tested. Cursor bounds are checked before merged capacity. The helpers' child-array and paired-row moves are shown in `instructions.tsv` and fixed witnesses, while `transfer-cases.tsv` and `child-cases.tsv` are synthetic local projections of these moves, not execution traces. The child projections cover the two sibling edge arrays and resulting child parent/index pairs, not parent-array compaction or allocator effects.

After a merge, an underfull parent is checked again. Let `current` be that parent's current occupancy and `sibling` the next selected sibling. A combined count `current + sibling + 1` below 12 merges; otherwise the helper borrows `5 - current` rows in the appropriate direction. An empty root reached by this upward path sets a flag for the caller; a nonempty root does not. The code in this packet stops at that flag and does not establish how the caller replaces the root. `upward-cases.tsv` includes local examples for both sibling directions and all counts below five.

### Failure branches and inference

`failures.tsv` derives 12 panic or unreachable-code text sites directly from PC-relative operands and literal descriptors. They cover a missing internal separator, merge cursor and capacity, both borrow capacity and source-count guards, child-height mismatch, and copy-length assertions. The empty-internal-node descriptor is the odd packed value 123, representing 61 bytes. These are static branches; the packet does not show that a valid withdrawal reaches them. Allocation, copying, and panic/unwind internals remain external.

Inference: the key and value arrays are the earlier packet's address and `(pending amount, pending count)` rows, based on the linked call chain, 20/16 byte widths, and previous state-layout evidence. The byte-level algorithms and offsets do not depend on that naming. The cursor adapter's predecessor substitution, global map-length change, root replacement, and any behavior beyond the selected windows are not proven by these local projections.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No compiled Rust comparison, normalized byte comparison, relocation equivalence, ABI closure, or whole-node equivalence is claimed. The Python tool uses fixed byte witnesses, FDEs and a bounded length decoder for a static map. Its branch and memory projections use synthetic fixtures and are checked against separately stated ordering and count invariants; they are not observed target execution.

## Results and limitations

- Four FDE windows contain 1,001 decoded instructions, with 127 transfer rows, 127 fixed byte witnesses, seven register-indirect copy bindings, seven raw direct-call candidates and two incoming calls. This denominator is only the four selected windows.
- Local fixtures: 275 initial choices, 125 upward choices, 66 leaf removals, 2,160 merge-cursor cases, 3,168 borrow-guard cases, and 1,078 cases each for paired-row and child-edge projections. Invalid small siblings are labelled by their input counts, not treated as valid tree histories. In the two transfer tables, `count=1` is a fixture marker for a merge, not a merge argument.
- The packet's 26 unittest tests pass without binutils, including corrupted input hash, every single witness, invalid and NOBITS addresses, invalid fixtures, branch-condition mutants and a branch into an instruction interior. The two independent regenerations above are byte-identical.
- Tests do not run node code, exercise allocator behavior, prove repair for arbitrary multilevel trees or validate the excluded caller's root replacement. No staking completion gate is requested.

Next question: can an independently authored implementation reproduce a multilevel removal sequence, including the excluded caller's root replacement and returned cursor, against an authorized target-grounded comparison?
