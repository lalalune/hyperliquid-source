# RE-006: insertion and split of a per-user order index on node 94

This packet establishes the position-dependent promotion and child relinking used when an inserted order-index entry splits a full node, allowing a reconstruction to preserve the target's 5/6-node distribution and parent links instead of treating the split as an opaque operation.

- Component ID: `orderbook`, task `RE-006` (book transitions).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is unlicensed and was used only for leads; no reference implementation is copied.
- Claim status: FDE records, bytes, relocation records, branch destinations, and displayed constants are observations. The data-structure and business labels below are inferences. The case table is a synthetic projection, not target execution.
- Scope included and excluded: two insertion wrappers, their shared leaf/parent split routine, and two bounded caller windows with cleanup. Other effects of the enclosing order handlers, the entry lookup, actual allocator behavior, complete unwinding behavior, and order matching are excluded.

## Reproduce

Run from the repository root with CPython 3.12.3 or a compatible Python 3 and the authenticated node #94 artifact. The collector imports the repository's ELF section and CIE/FDE parsers; it requires only the Python standard library otherwise. The SHA-256 of the complete artifact is checked before parsing. All VA reads require a unique file-backed section and exclude `SHT_NOBITS`; instruction observations are fixed byte windows, not text parsed from a disassembler. No external program is invoked by the collector or tests, and no captured executable is run.

```sh
python3 tools/artifacts.py verify
python3 tools/book_trigger_insert_split94.py --out research/work-items/RE-006-trigger-index-insert-split-94
python3 -m unittest tests.test_book_trigger_insert_split94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-trigger-index-insert-split-94 && sha256sum -c MANIFEST.sha256)
```

To check reproducibility, substitute a writable relative directory for `<tmp-dir>`:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_trigger_insert_split94.py --out '<tmp-dir>/a'
PYTHONHASHSEED=4937 TZ=Pacific/Honolulu python3 tools/book_trigger_insert_split94.py --out '<tmp-dir>/b'
diff -r '<tmp-dir>/a' '<tmp-dir>/b'
diff -r -x README.md -x MANIFEST.sha256 '<tmp-dir>/a' research/work-items/RE-006-trigger-index-insert-split-94
```

Recorded environment: Linux x86-64, CPython 3.12.3 and GNU objdump 2.42. Objdump was used only for manual instruction-boundary interpretation and the human excerpt in this README. It is not an input to the generated files. The collector and tests also ran with a Python-only `PATH` containing no binutils. `MANIFEST.sha256` covers this README and every generated evidence file.

## Evidence

All addresses are linked ELF virtual addresses; ends are exclusive. Section-derived file offsets, FDE/CIE/LSDA coordinates, raw bodies and SHA-256 hashes are in `functions.tsv`. The three selected indexed FDEs are:

| Selected role | Start | End | Bytes | FDE VA |
| --- | ---: | ---: | ---: | ---: |
| Search and insert A | `0x28526f0` | `0x285296c` | 636 | `0x1104588` |
| Search and insert B | `0x28577e0` | `0x2857a5c` | 636 | `0x11048e4` |
| Leaf insertion and upward split | `0x1ad5cd0` | `0x1ad73ea` | 5914 | `0x1017a64` |

An FDE is an unwind-described extent; it is not proof of all original source-level function boundaries or a whole-program census. Two direct call sites, `0x26e74d1` and `0x26e615d`, pass a pointer advanced by `0x38`, an eight-byte key, and a value buffer to the respective wrappers. Calls at `0x28527f4` and `0x28578e4` reach the shared split routine. The two caller windows are context only: neither enclosing caller is a newly selected subject.

The earlier [user-cancellation evidence](../RE-006-user-book-cancel-94/README.md) identifies a user entry with a second tree at `+0x38`; the earlier [placement evidence](../RE-006-order-place-route-94/README.md) observes an order-index insertion with an `0xb8`-byte value while leaving its split routine stubbed. The key and value geometry here agrees with that family. The interpretation that these particular call sites insert an untriggered order is a cross-packet inference, not a recovered symbol or an independent proof of every value field. The selected three FDEs are distinct from the earlier insertion, user-entry and deletion subjects.

### Search, replacement, and first leaf

The wrappers take result storage in `rdi`, a tree header in `rsi`, a key in `rdx`, and a pointer to a value in `rcx`. A null root takes the new-leaf branch. Otherwise, a u16 count controls an ascending u64 key search; the condition codes are unsigned. If a key is equal, the wrapper copies the old `0xb8` bytes to the result and copies the incoming `0xb8` bytes into the same value slot; the tree header count is not incremented on that path. The result's first word is whatever the old value held, including the possibility of `2`; the validity and interpretation of such a stored value are not resolved here.

If a key is absent and the root is null, allocation requests `0x850` bytes. The wrapper writes a null parent, initializes the count, sets root and height, and writes the first key and value. A non-null leaf is handed to the split routine. Successful insertion of a new key increments the qword at tree header `+0x10`, then writes qword `2` as the result's first word. The increment has no local overflow check in the recorded instructions; wraparound on an invalid maximum count is a mechanical consequence, not a claim that such a state is reachable.

After the call, both bounded caller windows compare only the result's low dword with `2`. For a different value, they test the qword at result `+0x30`; when nonzero they pass the pointer at `+0x38` and eight times that qword to the relocated deallocation slot. This describes the observed cleanup branch, not all ownership or rollback behavior.

### Node geometry

| Relative offset or size | Byte-backed observation |
| --- | --- |
| header `+0x00`, `+0x08`, `+0x10` | root pointer, descent height and incremented count |
| node `+0x00` | parent pointer |
| node `+0x08`, stride `0x08` | ordered keys |
| node `+0x60`, stride `0xb8` | values copied and shifted with keys |
| node `+0x848`, `+0x84a` | u16 parent-edge index and u16 live-key count |
| node `+0x850` | child pointers; each moved child's parent and index are rewritten |
| leaf / internal allocation | `0x850` / `0x8b0` bytes |
| node capacity | `0x0b` keys; child guard uses `0x0c` |

The byte offsets fit eleven key slots, eleven `0xb8`-byte value slots and twelve child slots. These region capacities are calculated from the observed offsets and allocation sizes; they are not a recovered Rust type declaration. `constants.tsv` records the exact immediate or displacement bytes used for these fields.

### Full-node split and propagation

For a valid full node of eleven old keys, let `i` be the insertion position among its twelve gaps. The following is a projection of the selected branch instructions and writes, with the old keys numbered from zero. It does not run the captured instructions.

| Insertion position | Old key promoted | New key placed | Final left keys | Final right keys |
| --- | ---: | --- | ---: | ---: |
| `0..4` | `4` | left at `i` | 5 | 6 |
| `5` | `5` | left at 5 | 6 | 5 |
| `6` | `5` | right at 0 | 5 | 6 |
| `7..11` | `6` | right at `i - 7` | 6 | 5 |

In particular, the key promoted is an old key; the inserted key is placed into one of the two nodes. This is not always the same rank in the twelve-key combined sequence. `split-cases.tsv` gives all twelve synthetic placements for both leaf and parent, including the projected child sequence for the parent cases. For a parent, the new right child is placed immediately after the insertion edge. The code shifts the affected keys, values and child pointers; writes the incoming key/value and child; and repairs affected children's parent pointer and u16 edge index. The same position tests appear in both leaf and parent paths.

The routine first splits a full leaf into the original node and a new `0x850`-byte sibling. With a non-null parent it either inserts the promoted pair into a parent with room or allocates an `0x8b0`-byte sibling and repeats upward. When propagation reaches the root, it allocates an `0x8b0`-byte new root, places the old root and sibling as children, updates parent/index fields and raises the header height. The selected conditionals are recorded in `branches.tsv`; this is a selected-site table, not a claim that all control-flow edges have been catalogued.

A short human-readable excerpt illustrates the leaf boundary; the retained byte windows are generated without objdump:

```text
1ad5cef  movzx ebx, WORD PTR [rbp+0x84a]
1ad5cf6  cmp   rbx, 0xb
1ad5d02  jb    1ad5d29
1ad5d08  cmp   rbx, 0x5
1ad5d14  jae   1ad5d5f
1ad5d16  mov   r12d, 0x4
```

### Failure and cleanup evidence

The branch table identifies distinct null-allocation arms for the initial leaf, split leaf, split internal node and new root. The allocator and failure handlers are identified by their relocation slots in `indirect-calls.tsv` and `relocations.tsv`; their bodies are not modeled. The split has separate guards for a sibling count outside its permitted range, a child-count bound, inconsistent child lengths, a null old root, height overflow, a height mismatch and a full new root. `diagnostics.tsv` ties five selected assertions to their literal bytes and relocated source-location records; it emits only a relative path suffix and a hash of the full embedded path.

Some failure paths occur after earlier tree writes, and the unwind regions include conditional deallocations. The selected bytes do not establish transaction-wide atomicity or restoration after an allocator failure or panic. The functions also do not validate arbitrary corrupted pointers before dereferencing them.

### Duplicate bodies and relocations

The insertion bodies are equal after masking the nine four-byte PC-relative operands listed in `twin-masks.tsv`. Each masked instruction's opcode and resolved target are checked independently; the masks do not cover branch conditions, constants or other bytes. Their common normalized body SHA-256 is `0fe03b4d2ae3f84b7faa5cc8e3ba394875b8a5701dd1c2c487487beb5ccb70cd`. This comparison is only between these two target windows, not source-to-target equivalence. Selected relocation records also bind the copy and overlapping-move slots to the ELF dynamic symbol names `memcpy` and `memmove`.

## Implementation and comparison

Independent Rust implementation: not yet implemented. A Rust build, helper closure, allocator comparison, raw/normalized source-to-target comparison, runtime fixture and whole-ELF comparison are not yet implemented or measured. No machine code is transplanted or executed.

The Python split projections check ordering, pivot position and, for parents, a derived child list; they do not emulate the node and are not differential tests. The validation suite checks the 24 projected position cases against independently stated expected pivots and ordering, rejects invalid positions, changes each of the 234 bytes of the 57 selected conditional branches, and exercises digest, witness, FDE, call, dynamic symbol, relocation and file-backed-range corruption controls. It also tests that the digest is rejected before FDE parsing.

## Results and limitations

The collector generates 3 FDE records, 49 pinned windows, 17 decoded constants, 57 selected conditional branches, 4 selected direct calls, 13 selected indirect calls, 6 selected relocation slots, 5 diagnostic records and 24 synthetic split cases. There are 16 unittest methods and no skipped tests. Two regenerations under different hash seeds and time zones produced identical files; the same targeted tests passed with no binutils on `PATH`.

No component progress gate is requested. The complete order placement route, the provenance of every caller argument, all malformed-tree effects, all indirect helper implementations and recovery after failure remain open. FDE membership, the two local body comparisons and the synthetic projections do not establish a build, behavioral equivalence, a function-coverage denominator or a complete node.

Next question: how do the surrounding order-placement callers recover or discard an already modified tree if a propagated split encounters an allocation or height assertion failure?
