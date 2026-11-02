# RE-006: how do spot level insert, split and field output read the tag?

The spot book path initializes level option words to 0 and writes 1 on append, but different consumers inspect different widths: split propagation compares the full first qword to 2, while the level formatter selects the `f` and `l` fields by comparing the low 32 bits to 1; a reconstruction can now preserve both decisions without guessing that their tests are interchangeable.

- Component ID: `orderbook`, task `RE-006`.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference was a search lead, not implementation material or proof.
- Claim status: the selected instruction bytes, FDEs and direct branch destinations are observations; the level/head naming is an inference from the call context and existing lifecycle evidence. Reachability and global tag invariants remain unresolved.
- Scope included and excluded: the spot price-level entry and its split/parent propagation helper, their search call sites, selected append-context bytes, the connected level-field formatting path, selected failure branches, and the split helper's LSDA table. The entire spot order, level deletion, all other level writers, deserialization, the bodies of the shared tree collector and numeric formatter, allocator and exception runtime, matching, settlement and Rust ABI are excluded. No selected function overlaps `RE-006-price-level-tree-insert-94`, which studies another instance and leaves the promoted-value invariant open.

## Reproduce

Run from the repository root with the authenticated artifact present. The collector uses Python 3 standard library and the repository `elf_index` and `fde_extents` modules; it never runs the target or invokes external programs. Author environment: Linux x86-64, Python 3.12.3. The evidence inputs are the authenticated ELF; file hashes are in `MANIFEST.sha256`. Substitute a writable relative directory for `<tmp-dir>`.

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/spot_level_tag94.py --out <tmp-dir>/a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/spot_level_tag94.py --out <tmp-dir>/b
diff -r <tmp-dir>/a <tmp-dir>/b
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/a research/work-items/RE-006-spot-level-tag-domain-94
python3 -m unittest tests.test_spot_level_tag94
(cd research/work-items/RE-006-spot-level-tag-domain-94 && sha256sum -c MANIFEST.sha256)
```

GNU objdump 2.42 was used only for human inspection, with `-d -Mintel` and explicit start/stop addresses; its output is not retained as generated evidence. For example, inspect the split helper and field writer with:

```sh
objdump -d -Mintel --start-address=0x1a94920 --stop-address=0x1a9566a artifacts/node/94/hl-node
objdump -d -Mintel --start-address=0x4a407a0 --stop-address=0x4a412d0 artifacts/node/94/hl-node
```

Every generated number, address, branch destination, selected byte sequence and FDE record comes from the ELF through fixed byte checks and the shared parsers. `split-cases.tsv` is a synthetic projection using immediate operands read from the checked instructions; it is not a captured execution. No masking is used.

## Evidence

All addresses are linked ELF virtual addresses; ends are exclusive. The generated records also contain file offsets. An FDE is an unwind range and does not alone prove an original source function boundary.

| Selected role | FDE range | Bytes | Evidence |
| --- | --- | ---: | --- |
| Level entry | `0x2878610..0x2878760` | 336 | `functions.tsv`, `witnesses.tsv` |
| Level insert and propagation | `0x1a94920..0x1a9566a` | 3,402 | same, plus `branches.tsv` and `unwind-sites.tsv` |
| `halfs` field formatter | `0x4a987c0..0x4a98b72` | 946 | two half calls and failure edges |
| One half's `levels` formatter | `0x431e040..0x431e29b` | 603 | field key and level-map call |
| Level-map wrapper | `0x460b7a0..0x460b866` | 198 | shared collector and pair writer |
| Level pair and option-field writer | `0x4a407a0..0x4a412d0` | 2,864 | `f` and `l` tests and payload calls |

The existing spot-order context selects `book+0x80` with a negated price when its side byte is zero, or `book+0x98` with the original price otherwise; it reaches the search, which calls the entry at the three sites in `calls.tsv`. The contextual call-site and append bytes are retained as windows, not claimed as newly analyzed functions. Prior `RE-006-price-level-lifecycle-94` and `RE-006-spot-order-insert-94` supply the queue and spot interpretation.

At the selected entry, an occupied result returns `node + index * 0x20` without the insertion/count-increment path. For a new value, the entry writes zero qwords at the new value's offsets `+0x00` and `+0x10`; it does not establish the contents of the other bytes. A new root uses an allocation request of `0x1c8` bytes, installs the node, and inserts the key and 32-byte value; an existing root calls the selected split helper. On normal return after either insertion, it increments the tree count at `+0x10`. Allocation failure and the node-capacity check have separately recorded targets.

In the selected spot append context, a byte test of the returned level's first field controls a full-qword store of 1 at `+0`, and the tail gets a full-qword store of 1 at `+0x10`. These are local observations, not a census of all writers. In particular, the byte test on an already nonzero head does not establish the other seven bytes of that qword. The intervening allocation helper could have effects beyond the retained windows; the ordinary interpretation assumes it does not change the saved level through an alias.

### The value and the marker

The split helper tests the node's 16-bit live count against 11. The unsplit arm stores a full qword 2 in its local result and tests that result. On a full leaf it reads the 32-byte promoted value, saves its **first qword** at stack `+0x18`, copies the later 24 bytes separately, inserts the incoming level and updates node counts. It then copies the saved first qword to the result slot and compares the complete qword to 2 at `0x1a94cb1`. Equality goes to the common return path; inequality continues to parent or root handling. `promoted_read`, `copy_and_truncate`, `insert_value` and `promoted_decision` in `witnesses.tsv` preserve this dataflow.

A full parent has a corresponding promoted-value load and full-qword comparison (`internal_promoted_read` and `internal_promoted_decision`); the parent and root paths use the same 32-byte value layout. The node fields selected by the entry and split code are values at `+0`, parent at `+0x160`, eight-byte keys at `+0x168`, parent index at `+0x1c0`, 16-bit count at `+0x1c2`, and internal child pointers at `+0x1c8`. The code requests `0x228` bytes for a new internal root. These are machine-layout observations, not a claim about source-level field names.

For the full-node input position, the checked branch operands lead to the following synthetic cases, also recorded individually in `split-cases.tsv`:

| Insertion index | Old pivot index | Incoming value side | Left / right counts |
| --- | ---: | --- | --- |
| 0..4 | 4 | left | 5 / 6 |
| 5 | 5 | left | 6 / 5 |
| 6 | 5 | right | 5 / 6 |
| 7..11 | 6 | right | 6 / 5 |

This arithmetic table assumes a valid, sorted, full node and successful allocation and copies. It is a prediction from selected bytes, not a target run or proof that those inputs occur.

### Connected level-field output

The existing book-formatting context passes `book+0x80` with the literal `halfs` to the selected field writer. That writer calls the selected half formatter with the first pointer and again with the pointer advanced by `0x18`. The half formatter supplies the literal `levels` and calls the selected level-map wrapper, which calls a shared collector followed by the selected pair writer. `calls.tsv` binds each direct edge; `literals.tsv` resolves the four RIP-relative string references and their encoded lengths directly from file-backed ELF bytes. The shared collector is a boundary already studied by open PR #1843: its output consists of 16-byte `(key pointer, value pointer)` pairs, with the value pointer formed as `node + index * 0x20`. This packet does not select or reanalyze that collector's FDE. Its prior observation connects the formatter's pair value to the level value being promoted.

The pair writer loads its second pointer, then the low 32 bits of that value at `+0` and `+0x10`. It emits field `f` only when the former dword equals 1, and field `l` only when the latter dword equals 1. Each emitted field passes the qword at the corresponding `+8` or `+0x18` to a numeric formatting helper. The selected instructions separately test the low byte before the payload path. Assuming the value is not changed through an alias by the intervening formatting calls, the low-byte-zero branch cannot follow a successful low-dword-equals-1 test; the bytes alone do not prove that absence of alias writes. Insertion and formatting are separate call paths over compatible level layouts; their relative scheduling is not established. This is an observed formatting path, not proof that the same format is used by a snapshot loader or that its serialized output is a complete persistence format.

The seven checked compare encodings, widths and immediate bytes are in `tag-uses.tsv`.

| Site | Tested portion | Observed decision |
| --- | --- | --- |
| Spot append head | low 8 bits | zero writes full-qword 1; nonzero skips that write |
| Split propagation | all 64 bits | equals 2 takes the no-propagation branch |
| Level field `f` | low 32 bits | equals 1 enters its field-output path |
| Level field `l` | low 32 bits | equals 1 enters its field-output path |

On canonical full-qword values 0 and 1 these decisions are compatible. The width differences are machine-level facts; no assertion is made that noncanonical representations are reachable.

### Failure and unwind evidence

`branches.tsv` lists 44 selected conditional branches with their original opcode, fallthrough and decoded target, including allocation, copy bounds, height, root and node-capacity branches. `calls.tsv` separates eighteen direct relative calls from nine RIP-relative indirect call **slots**; a slot address is not itself proof of the final runtime callee. The split FDE has an LSDA at `0x966314`: `unwind-sites.tsv` retains all 10 rows of its encoded call-site table. For example, the bounds-failure range `0x1a95595..0x1a955ac` has landing pad `0x1a95632`, whose selected bytes call the free slot with size `0x1c8` and then resume via the direct call recorded in `calls.tsv`. Other table rows point to different landing pads, including internal-node cleanup. `relocations.tsv` retains the three selected relative slot relocations and the unwind PLT jump-slot relocation. The PLT bytes address the latter slot, whose dynamic symbol is `_Unwind_Resume`; the allocation and release role labels come from calling context, and the relative addends are recorded without asserting their complete behavior. No exception runtime is executed, and these records do not establish rollback or that any failure is reachable from valid order input.

### Inferences and open invariants

The first and third qwords are interpreted as the head and tail option tags because the surrounding spot append manipulates the returned value as the two queue endpoints; an FDE does not identify the original Rust type. Constructor zero and the shown append stores of one are consistent with 2 being reserved for the helper's no-propagation representation. They do **not** prove that every value promoted from every pre-existing or deserialized level has a first qword in `{0,1}`, nor that all writers preserve canonical high bytes. Proving that invariant requires a complete writer and state-loading analysis. The observed full-qword compare must not be replaced with a low-byte compare on the basis of these observations alone.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Compiler, linker, lockfile, helper closure, relocation/vtable closure, raw and normalized Rust-to-target comparison, and two-build result: **not yet measured**. There are no comparison masks. The 12 split rows are explanatory model cases; they do not execute, emulate or compare against the node. Negative controls change selected hashes, bytes, FDE bounds, branch and call encodings, LSDA bytes, and non-file-backed address requests. The captured binary and visor were not executed.

## Results and limitations

The bounded packet records 6 FDE ranges totaling 8,349 bytes, 36 selected byte windows, 44 selected conditional branches, 27 selected call sites, 4 ELF literals, 7 fixed tag tests, 4 selected relocation records, 10 LSDA rows and 12 synthetic split cases. These are selected evidence counts, not a function-coverage denominator. The focused 17-test suite passed without skips; two regenerations under different hash seeds and time zones matched each other and the evidence with binutils absent from `PATH`.

No RE-006 completion gate is requested. The evidence does not establish all writers, all control-flow paths, valid-state reachability, exception side effects, alias freedom, a target ABI or target equivalence. The collector and numeric helper bodies, other relocations, vtables, data ownership and the whole ELF remain outside this comparison. Next question: trace the independent level deserializer and every deletion/update writer of the first qword, then prove or qualify the full-width `{0,1}` invariant over restored and live books.
