# staking: vote-jail tracker nested insertion in node #94

This packet establishes how the vote-jail tracker's target-row and inner-row insertion helpers handle vacant cursors, node splits, and allocation failures, enabling reconstruction of operations that were stubbed in the earlier action study.

- Component ID: staking (validator lifecycle and signer jailing).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead, not a source of implementation.
- Claim status: observations are distinguished from inferences below; reachability and cleanup beyond the selected helpers remain unresolved.
- Scope included and excluded: the complete FDE windows of the two insert helpers, their direct call instructions, their reached allocation/copy boundaries, and synthetic cursor fixtures. The already studied vote handler, its adapters, quorum computation, row deletion, and unwinding are outside the evaluated code.

## Reproduce

From the repository root, with Python 3.12.3 and the checked node #94 artifact:

```sh
python3 tools/staking_vote_jail_insert94.py --out research/work-items/staking-vote-jail-nested-insert-94
python3 -m unittest tests.test_staking_vote_jail_insert94
```

The tool verifies the full input digest before analysis, uses the shared ELF and FDE parsers, and reads the binary as data. It does not launch the node or invoke binutils. It decodes target instruction bytes with a bounded interpreter; allocator, `memcpy`, `memmove`, and terminal failure boundaries are simulated. No network, key, chain, or node execution is involved. The generated TSV files and this README are covered by `MANIFEST.sha256`.

To compare independent regenerations with different hash seeds and time zones:

```sh
mkdir -p work/jail-check-a work/jail-check-b
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_vote_jail_insert94.py --out work/jail-check-a
PYTHONHASHSEED=9381 TZ=Pacific/Honolulu python3 tools/staking_vote_jail_insert94.py --out work/jail-check-b
diff -r work/jail-check-a work/jail-check-b
```

## Evidence

All addresses below are virtual addresses in the pinned ELF; `functions.tsv`, `anchors.tsv`, and `calls.tsv` include corresponding file offsets and bytes. Ends are exclusive FDE ends, not inferred symbol sizes. `call-candidates.tsv` scans every file-backed executable section for the fixed `E8 rel32` byte pattern targeting either helper; it is a byte scan, not an assertion that arbitrary matches are instruction starts. The two resulting sites are independently identified direct calls.

| Role | FDE window | Direct call site | Entry representation |
| --- | --- | --- | --- |
| Target row | `0x2f3d5c0..0x2f3e68e` | `0x33c21eb` | 20-byte key, 32-byte value |
| Inner row | `0x2f9cc50..0x2f9d814` | `0x33c24d2` | 48-byte value; no separate key bytes passed to this helper |

The first call supplies a cursor, key bytes, and value bytes; the second supplies a cursor and value bytes. The earlier `staking-c-signer-jail-94` action study connects these call paths to opening the vote tracker, but stubbed their adapters. This packet evaluates the two distinct helper bodies, rather than the already recorded action or adapters.

The target-row node stores eleven 32-byte value slots starting at `+0`, its parent pointer at `+0x160`, eleven 20-byte keys at `+0x168`, its parent edge at `+0x244`, and its 16-bit count at `+0x246`. Children of an internal node start at `+0x248`. A leaf allocation is `0x248` bytes and an internal allocation is `0x2a8` bytes. The inner-row node stores eleven 48-byte values starting at `+0`, its parent pointer at `+0x210`, parent edge at `+0x218`, count at `+0x21a`, and internal children at `+0x220`. Its leaf and internal allocations are `0x220` and `0x280` bytes. Pointer back-links, child indices, in-order records, returned cursors, allocation sequences, and map descriptor lengths are checked in the exercised fixtures.

For a selected leaf with fewer than eleven entries, both helpers insert at the supplied gap and move the suffix when needed. For a full selected leaf, the model and byte evaluation agree on these root-leaf split outcomes; pivot numbers refer to zero-based positions in the old leaf:

| Insertion gap | Old pivot | Left count | Right count |
| --- | --- | --- | --- |
| 0–4 | 4 | 5 | 6 |
| 5 | 5 | 6 | 5 |
| 6 | 5 | 5 | 6 |
| 7–11 | 6 | 6 | 5 |

The outer and synthetic inner fixtures also cover a parent with room, a full parent, and cascades through three full ancestors. The independent model checks promoted entries and the resulting full tree shape; the executable slice supplies the actual operations. The helpers leave the descriptor's total-length word unchanged in these fixtures. The caller's length maintenance is outside this packet.

`controls.tsv` records four injected allocator failures across the two root-leaf splits and ten corrupted metadata cases across both helpers. Each reaches a terminal boundary recorded there; the interpreter stops at that boundary, so these cases do not establish unwind cleanup or recovery. `branches.tsv` gives bytes, branch targets, and observed outcomes. `relocations.tsv` identifies the relocation records used to install the simulated external boundaries.

### Inferences and unresolved questions

- The first helper is the target-address tracker map insertion and the second inserts a nested tracker value, based on the direct calls and the earlier action study. These names are functional labels, not recovered source symbols.
- The absence of key bytes in the inner helper is consistent with a zero-sized key, but this packet does not prove its Rust type or global map invariants. The single empty-leaf case is a useful local boundary; the 77 nonempty inner leaf fixtures and 414 multi-level fixtures deliberately exercise raw machine behavior and are **not** claimed to be reachable valid vote-jail states.
- The combined fixtures hand an empty inner leaf to the second helper after the first returns. This bridge is constructed by the harness; neither adapter nor its allocation and length updates are executed. Existing outer values are opaque synthetic payloads. The harness supplies the insertion cursor and its synthetic key order; target lookup, key comparison, and cursor production are not evaluated.
- Unit-key uniqueness, actual caller reachability of a retained empty inner root, all indirect targets, allocation-failure unwinding, and downstream vote/cleanup behavior remain to be established independently.

## Implementation and comparison

Not yet implemented. No Rust component, dependency lock, compiler comparison, whole-ELF comparison, or normalization mask is claimed. The test model is an independent insertion specification for synthetic fixtures, not a source reconstruction or proof of binary equivalence. The checked binary's instruction bytes are evaluated, with allocation, byte-copy and failure boundaries simulated as described above.

## Results and limitations

- Outer helper: 492 fixtures: 78 leaf, 372 one-parent and 42 multi-ancestor cases. Each is checked against the independent ordered-tree model, including the returned position.
- Inner helper: 492 fixtures: 78 leaf, 372 one-parent and 42 multi-ancestor cases. One leaf starts empty; the other 491 fixtures have synthetic nonempty contents. The model checks the ordered payload sequence, full tree shape, parent links and returned position.
- Combined helpers: 110 synthetic fixtures, with the transition between helpers supplied by the harness. There are fourteen recorded failure/corruption controls.
- Linear FDE decoding yields 845 outer and 629 inner instructions. Synthetic evaluation reaches 761 and 545 instruction starts, respectively; 29 of 40 outer conditional sites and 29 of 38 inner conditional sites have both outcomes observed. `coverage.tsv` gives both reached and total conditional-site counts. This denominator is selected FDE decoding only, not node-wide function coverage.
- The focused unittest module has 21 tests and no skips. Different hash seeds and time zones produce byte-identical evidence with binutils absent from `PATH`.
- No progress gate is requested. The concrete next question is which valid action states can produce an empty retained inner root and whether any other path can create multiple inner rows.
