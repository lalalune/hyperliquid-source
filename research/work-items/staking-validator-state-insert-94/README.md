# staking: validator state map insertion and lookup in node 94

This packet recovers how a newly registered validator's state row enters the ordered map, including the position-dependent split and promotion rules, so a reconstruction can preserve the complete 28-byte state and return the inserted row's cursor even when splits propagate to a new root.

- Component ID: `staking`, validator lifecycle and stake accounting.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead, not implementation source.
- Claim status: the instruction bytes, selected call sites, ELF relocations, FDE extents, and bounded interpreter outcomes are observations. The action and field names follow the earlier staking action and state-wire packets and are inferences about the relationship to these instructions. Conditions outside the selected helpers and behavior beyond the modeled boundaries remain unresolved.
- Scope included and excluded: the complete unwind ranges for the nonempty-map insertion helper and state-row lookup helper, plus selected call-site bytes connecting them to registration and profile change. The previously analyzed action host and insertion adapter are context only. Authorization, duplicate replacement, initial empty-map allocation by the adapter, allocator internals, exception unwinding, validator eligibility, #115, and a complete node implementation are excluded.

## Reproduce

From the repository root, with Python 3.12 and the authenticated target:

```sh
python3 tools/artifacts.py verify
python3 tools/staking_validator_state_insert94.py --out research/work-items/staking-validator-state-insert-94
python3 -m unittest tests.test_staking_validator_state_insert94
(cd research/work-items/staking-validator-state-insert-94 && sha256sum -c MANIFEST.sha256)
```

The generator checks the full artifact SHA-256 before parsing, uses `tools/elf_index.py` and `tools/fde_extents.py`, and excludes SHT_NOBITS from file-backed byte resolution. It checks fixed instruction signatures and both complete body hashes before decoding; section, instruction, displacement and relocation records come from the ELF bytes. The Python instruction interpreter is adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`, with its license retained. It interprets selected bytes using bounded memory and modeled callees; it does not launch the captured binary, call an external program, use a network or load keys. The human-readable instruction excerpts below were checked with GNU objdump 2.42; generator output does not parse or contain objdump output. Python version used here: 3.12.3, Linux x86-64.

The determinism check uses two distinct writable relative output directories; replace the placeholders before running:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_validator_state_insert94.py --out <tmp-dir-1>
PYTHONHASHSEED=917 TZ=Pacific/Honolulu python3 tools/staking_validator_state_insert94.py --out <tmp-dir-2>
diff -r <tmp-dir-1> <tmp-dir-2>
```

`functions.tsv` binds the two body hashes and unwind ranges. `pins.tsv` binds selected incoming call and field-access bytes. `relocations.tsv` binds modeled slots to ELF relocation records and dynamic symbol names. `instructions.tsv` and `branches.tsv` are byte-decoder records. `insertions.tsv`, `leaf-splits.tsv`, `deep-splits.json`, `lookups.json`, `allocation-failures.json`, `branch-mutations.json` and `summary.json` are generated together. `MANIFEST.sha256` covers these files and this README.

## Evidence

All code addresses below are ELF virtual addresses, and all ranges are half-open. The corresponding file offsets are in `functions.tsv` and `pins.tsv`. FDE extents describe unwind ranges; they do not establish a complete function census.

| Role | VA range | File offset at start | Body SHA-256 |
| --- | --- | --- | --- |
| Nonempty-map insertion | `0x2f98850..0x2f99816` | `0x2f97850` | `a7197d7923701c36fe1781eee590192ac2021d98d7e3b3d7d16ba060d28f6b71` |
| State-row lookup | `0x33adde0..0x33adeba` | `0x33acde0` | `ec40682ba3318ddab7590a46fab361b9c9b4a0d150acfe583ca5de598770fb95` |

The earlier state-wire packet identifies `S+0x278` as the `validator_to_state` map and its value as two 12-byte times followed by `delegations_blocked`. Here `0x3995825` takes that field's address, `0x3995838` clears the byte at offset 24 of the registration value, and `0x399586f` calls the insertion adapter. The adapter calls the insertion helper at `0x33a1d11` and increments the map count at `0x33a1d9c` on the new-row path. In the profile-change slice, `0x3995bb6` takes the same field's address and `0x3995bc0` calls the lookup helper. These are context pins; the enclosing functions are not part of the claimed ranges.

### Layout and lookup

The helpers use 20-byte keys, 28-byte values, and nodes with these offsets:

| Node offset | Observed role |
| --- | --- |
| `+0x00` | parent pointer, zero for a root |
| `+0x08` | first of up to 11 keys, stride 20 |
| `+0xe4` | first value, stride 28 |
| `+0x218` | two-byte parent edge index |
| `+0x21a` | two-byte occupied-key count |
| `+0x220` | first child pointer for an internal node, stride 8 |

Leaf allocations request `0x220` bytes; internal-node allocations request `0x280`. The lookup loads a 20-byte compare length and calls the GOT slot `0x576e488`; its relocation identifies `memcmp`. It scans keys in order, returns the matching value pointer, and follows the selected child otherwise. A null root or a missed key at leaf height returns zero. Its five conditional branches have both outcomes covered by the ordinary fixtures, including 20 keys that differ at each byte position and absent keys before, between and after present keys.

### Insertion and split

The insertion helper takes an already selected leaf cursor, key and value. It does not search for duplicates or increment the map count. With fewer than 11 keys it shifts the suffix when needed, writes both key and value, increments the node length, and returns the inserted cursor. The entry branch is visible in the target bytes:

```text
0x2f98872: 48 83 fb 0b    cmp rbx, 11
0x2f98876: 73 2d          jae 0x2f988a5
```

For an 11-key leaf, indices refer to the vacant insertion position and old-key positions are zero-based. The pivot is selected before inserting the new key:

| Insertion position | Old key promoted | Final left / right counts | New cursor |
| --- | --- | --- | --- |
| 0 through 4 | 4 | 5 / 6 | left, original index |
| 5 | 5 | 6 / 5 | left, index 5 |
| 6 | 5 | 5 / 6 | right, index 0 |
| 7 through 11 | 6 | 6 / 5 | right, index minus 7 |

`leaf-splits.tsv` gives the 12 target-byte outcomes with concrete keys. The new key stays in a leaf in these cases; the pivot is an old key. A full parent is split by the same position classes, and the promotion continues upward. A split reaching a node without a parent causes a new root to be allocated and raises the root height. `insertions.tsv` checks every insertion position in full children under parents of 1, 5, 10 and 11 keys, including all 12 child positions of a full parent. The 576 `deep-splits.json` cases start with a full height-two tree and exercise all 12 by 12 ancestor-edge combinations, with four leaf positions covering the four pivot classes, through two full ancestors into a new root; they compare the entire ordered key/value sequence, allocation sizes, parent pointers, parent edge indices and the returned cursor. The map count is deliberately unchanged by this helper, matching the separate adapter increment above.

A selected value byte is also used as an internal control in the split path: `0x2f98ce4` compares it with 2. The state-wire packet identifies that byte as a boolean, so fixtures use only 0 and 1; the sentinel and malformed in-memory representations must not be treated as ordinary validator-state values. The other 24 value bytes are opaque payload in these fixtures and their calendar validity is not tested.

### Failure boundaries and controls

`allocation-failures.json` makes each of the three allocation calls in a leaf-plus-parent root split return zero in turn. The byte interpreter reaches the corresponding modeled allocation-failure boundaries at `0x2f99775`, `0x2f99731`, and `0x2f99792`. These are injected allocation failures, not observed operating-system failures; this packet makes no rollback or unwind claim. The harness models `memcmp`, `memcpy`, `memmove`, allocation, deallocation and terminating failure calls. Its pointers, allocation behavior and initial trees are fixtures, not captured runtime state.

Every decoded conditional branch is inverted separately in the interpreter, then replayed against one or two previously passing witnesses. `branch-mutations.json` records the changed opcode, witness and reason. The corruption controls detect a mismatch, modeled failure, or access outside the fixture; such outcomes are properties of the bounded model and do not establish target behavior for corrupted code. The tests separately reject a bad artifact digest, changed body and context bytes, an interior FDE address, out-of-range or NOBITS reads, invalid fixture indices, and three changed branch opcodes.

### Inferences

The `validator_to_state` and boolean field names come from the previously mapped serializer and action context, not from symbol names in these stripped functions. The observed layout and `S+0x278` call sites connect these helpers to that map; they do not prove that every write to the field uses this path. The reference's staking definitions are incomplete leads and were not copied into the implementation.

## Implementation and comparison

Not yet implemented. There is no Rust component, source build, byte-window comparison, or normalized comparison in this packet. The helper interpreter and sorted-map fixture are analysis tools, not a reconstructed node. No operand is masked in the recorded target byte checks. Calls to allocator and memory routines are modeled; their actual implementation, data dependencies, relocation closure, cross-component calls and whole-ELF equivalence remain unmeasured.

## Results and limitations

The generator records 2 FDE ranges, 888 decoded instructions, and 46 conditional branches. Across the ordinary insertion, deep-tree and lookup fixtures, 816 instruction addresses and both edges of 28 conditional branches were reached; these are bounded fixture counts, not function or component coverage. All 404 insertion cases, 576 deep-tree cases and 24 standalone lookup cases agree with the sorted key/value model. All 3 injected allocation failures reach modeled failure boundaries. Each of the 46 single-branch inversions is detected by at least one recorded witness; 0 survive and 0 are unreached in this mutation experiment. Sixteen focused unittest methods pass with no skips.

The fixtures cover valid sorted unique keys, ordinary boolean values and up to height three after insertion. They do not establish behavior for malformed node graphs, duplicate keys, other field writers, exhaustive input states, actual allocation failure cleanup or the original allocator. Code bytes that ordinary cases did not reach and other indirect control paths remain gaps. No staking milestone or whole-node gate is advanced. Next question: under what independently verified validator lifecycle conditions is an existing blocked row removed and later registered again, and how does that interact with the separately mapped unregister path?
