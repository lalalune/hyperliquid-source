# staking: delegation book insertion and upward splits in node 94

This packet establishes how missing address rows are inserted into both outer and inner staking books, including the two node layouts, split pivot, promotion, parent-link repair and root growth needed to reconstruct the bookkeeping path.

- Component ID: staking (staking and validator lifecycle; stake accounting for node 94).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference tree was a lead only; no reference implementation is copied.
- Claim status: byte and relocation observations and finite static-evaluator results below; book names are inferred from the existing stake-accounting packet. Untested behavior is listed under limitations.
- Scope included and excluded: the complete unwind extents of four address-key insertion bodies, including their internal upward split and failure branches, six incoming call sites and four caller length-increment sites. Existing staking entry and accounting bodies are context only. Search, occupied-entry replacement, caller admission rules, outer rollback, allocator implementation and removal are excluded. Node #115 is excluded.

## Reproduce

From the repository root, with Python 3.12 and the standard library:

```sh
python3 tools/staking_delegation_insert94.py --out research/work-items/staking-delegation-insert-94
python3 -m unittest tests.test_staking_delegation_insert94
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_delegation_insert94.py --out work/staking-insert-a
PYTHONHASHSEED=9241 TZ=Pacific/Honolulu python3 tools/staking_delegation_insert94.py --out work/staking-insert-b
diff -r work/staking-insert-a work/staking-insert-b
```

Use fresh output directories for the comparison. `MANIFEST.sha256` records the output and this README. The tool verifies the entire input digest first, imports the repository ELF and FDE parsers, checks exact body hashes and fixed instruction-byte anchors, reads relocation and symbol records itself, and never starts the captured executable. It runs without binutils in `PATH`. The instruction evaluator is adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`; allocation, memory copies and failure sinks are simulated. Fixtures are synthetic, have no external side effects, and all numbers and rows in the generated files come from bytes or explicitly identified test inputs.

For an optional human-readable inspection with GNU objdump 2.42:

```sh
objdump -d -Mintel --start-address=0x2f0cf20 --stop-address=0x2f0dc10 artifacts/node/94/hl-node
```

The objdump text is not input to the generator or the tests.

## Evidence

Addresses are linked ELF virtual addresses, not runtime-rebased addresses; file offsets and SHA-256 hashes of each body are in `functions.tsv`. FDE starts, exact end addresses, selected input sections and relocation records are decoded from the checked ELF. The four starts are targets of the direct-call bytes in `incoming-calls.tsv`; normal and failure exits are in the decoded windows. An FDE describes an unwind range, and does not establish a whole-program function census.

| Role in previously mapped staking accounting | FDE interval (VA, half-open) | Incoming call sites |
|---|---|---|
| Validator-member/delegation rows | `0x2f0cf20..0x2f0dc10` | `0x33bda38`, `0x33bf7cb`, `0x33c2b8b` |
| User-balance rows | `0x2f14bc0..0x2f158b0` | `0x33bc128` |
| User-to-delegations outer rows | `0x2f62b10..0x2f63987` | `0x33bf91b` |
| Validator-to-member-group outer rows | `0x2f490b0..0x2f49f75` | `0x33c236b` |

The roles derive from the entry operations described in `staking-stake-accounting-94`; those earlier functions already cover the bookkeeping and are not re-claimed here. The input at `rsi` is a cursor `(node, level, gap)`, `rdx` points to a 20-byte key and `rcx` to a value. The output at `rdi` is a cursor to the inserted item. On the full-node route `r8` supplies access to the root descriptor. The calls do not perform the key search: the incoming cursor must already identify the vacant gap. The included incoming calls are selected staking-path anchors, not an exhaustive caller census; an insertion body is also called in other contexts, so exclusive staking ownership is not established.

| Node field | Three 24-byte-value bodies | 32-byte-value validator-group body |
|---|---|---|
| Parent pointer | `+0x00` | `+0x160` |
| Values, including stride | `+0x08`, 24 bytes | `+0x00`, 32 bytes |
| Address keys, including stride | `+0x110`, 20 bytes | `+0x168`, 20 bytes |
| Index in parent, 2 bytes | `+0x1ec` | `+0x244` |
| Occupied key count, 2 bytes | `+0x1ee` | `+0x246` |
| Internal child pointers, 8-byte stride | `+0x1f0` | `+0x248` |
| Allocation request for a leaf / internal node | `0x1f0` / `0x250` bytes | `0x248` / `0x2a8` bytes |
| Full node threshold | 11 keys | 11 keys |

`anchors.tsv` contains fixed-byte checks of the count and allocation instructions, and the complete decoded bodies and branch destinations are in `instructions.tsv` and `branches.tsv`. The symbol-bound copy slots and relative relocation targets used at the simulation boundaries are in `relocations.tsv`. The first two routines differ at 107 raw byte positions, retained in `raw-differences.tsv`; no bytes are masked and no whole-function identity is asserted. No raw comparison is claimed for the other two bodies. Instruction rows are a linear decode of each FDE; boundaries in unreached bytes are not independently established as reachable code.

### Successful insertion and propagation

1. A node with fewer than 11 keys receives the new key and value at the supplied gap. If the gap is before the end, overlapping moves open matching key and value slots. Its key count rises by one and the output cursor identifies the inserted value.
2. A full leaf is split. The position of the incoming item determines which **old** key is promoted, not simply the middle of the twelve resulting items:

| Incoming gap | Promoted old slot | Left count after insert | Right count after insert |
|---|---:|---:|---:|
| 0 through 4 | 4 | 5 | 6 |
| 5 | 5 | 6 | 5 |
| 6 | 5 | 5 | 6 |
| 7 through 11 | 6 | 6 | 5 |

3. The promoted key and value and the new right child enter the parent at the old child's edge. An internal node with room stops propagation. A full internal node is split by the same gap rule, its moved child pointers acquire new parent and edge-index fields, and its promoted pair continues upward.
4. If the split reaches the root, a new internal node is allocated, both children receive the new parent and edge indices, and the root descriptor's height increases. The returned cursor still identifies the original inserted key and value, even if multiple levels split.
5. The insertion bodies do not increment the map's total length in the tested cases. `caller-post-sites.tsv` pins the caller increments after each of the four mapped entry paths. This distinction matters when integrating the helper with the surrounding entry code.

`cases.tsv` records the exact input shape, selected gaps, allocation sequence, returned slot and hash of the entire resulting logical tree for 3,896 normal cases. The oracle is a separate Python insertion model: it compares every key/value and the complete child shape, checks all parent links and edge indices, and checks the returned cursor and allocation sequence. All four bodies run for every case. Fixtures cover every leaf size and gap, every child edge for four parent sizes, and selected three- and four-level cascades. Keys share an ordered prefix and exercise all 20 bytes; synthetic values exercise all 24 or 32 bytes as opaque data. These are finite synthetic cases, not a test of all possible machine states or of the validity and ownership of the nested map values.

### Failure and corruption controls

`controls.tsv` preserves the reached failure-site address and allocation sequence. For each body it covers a failed leaf allocation, failed internal allocation, failed new-root allocation, failed root allocation after an internal split, a mismatched cursor level, a missing root, corrupted leaf and parent counts, root-height overflow and a root-height mismatch. These checks establish that the evaluated path reaches the corresponding failure sink; the sink itself is not reconstructed and no rollback guarantee is inferred.

Four further byte edits per body alter the full-node threshold, the low pivot, the last-key-word store offset, and the full-node conditional. Each is rejected by the independent tree model. The unit tests also reject a wrong complete binary digest, a non-start FDE address, a file-unmapped address, an invalid byte range and a changed anchor or call opcode, and a mutated jump outside the selected FDE. The evaluator stops if control leaves that FDE.

## Implementation and comparison

Independent Rust: not yet implemented. Compiler and linker flags, build provenance, fixtures from a running node, and raw or normalized compiled-Rust comparisons: not yet measured. No machine-code bytes are transplanted into a Rust implementation. No normalization masks are used. The generator does not claim allocator, memory-copy, failure-sink, relocation-target, vtable, data-section or whole-ELF equivalence; its simulated boundaries and exact relocation records are explicit.

## Results and limitations

- 3,896 normal tree cases and 60 failure or mutation controls were generated with no model mismatches; 17 unit tests passed with no skips.
- The two inner-row bodies each contain 696 decoded instructions, of which 657 were reached; the user-book body reached 687 of 764 and the validator-group body reached 705 of 783. Each has 38 conditional sites, all reached, with both outcomes seen for 31 sites. Seven conditional sites per body retain an unobserved outcome (`branches.tsv`). Reaching a site does not prove all paths through it.
- These bodies accept an already chosen gap. The code that finds that gap, duplicate-key behavior, allocation failure aftereffects, all unwind cleanup, and semantics outside these four instances remain open. The tree model tests valid, finite fixtures and selected corruptions, not all possible memory states.
- No progress gate is requested and no component or whole-node equivalence is claimed.

Next question: can an independently authored Rust address-map insertion reproduce both node layouts and returned cursors across deeper trees and the untested unwind and allocation-failure paths?
