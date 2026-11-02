# staking: delegation-book teardown and unwind cleanup in node #94

Node #94 tears down the user and validator delegation books through different outer row strides but the same nested-tree destructor, so an independent reconstruction can preserve the two ownership layouts, child-before-parent releases, and the remaining-book cleanup on the studied unwind paths.

- Component ID: `staking` (staking and validator lifecycle; delegation ownership).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; no reference implementation is copied.
- Claim status: ELF/FDE/LSDA bytes and direct call sites are observations. The results of the byte interpreter are conditional on the synthetic memory and modeled boundaries below. The field names and their connection to delegation accounting are inferences joined to the existing staking packets. Untested runtime behavior remains unresolved.
- Scope included and excluded: six previously unselected FDE ranges in `functions.tsv`, including both outer destructors, the shared nested destructor, two residual-iterator cleanup functions, and the two-book cleanup wrapper. Selected byte windows in already studied callers are linkage context only. The outer iterator implementations, allocator, real unwinder, whole accounting functions, all other cleanup paths, node #115 and actual target execution are excluded. No component gate is requested.

## Reproduce

Run from the repository root with Python 3.12 and the standard library. The generator authenticates the complete input SHA-256 before parsing, imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`, ignores `SHT_NOBITS` for file-byte mappings, and reads the instructions, RELA entries and exception call-site records directly from ELF bytes. The x86 subset decoder and interpreter are adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`. No external program or captured executable is started by the tool or tests.

```sh
python3 tools/artifacts.py verify
python3 tools/staking_delegation_drop94.py --out research/work-items/staking-delegation-drop-94
python3 -m unittest tests.test_staking_delegation_drop94
python3 tools/catalogue.py --check
(cd research/work-items/staking-delegation-drop-94 && sha256sum -c MANIFEST.sha256)
```

For the deterministic comparison, substitute two distinct empty writable relative directories for the placeholders:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_delegation_drop94.py --out <tmp-dir-1>
PYTHONHASHSEED=719 TZ=Pacific/Honolulu python3 tools/staking_delegation_drop94.py --out <tmp-dir-2>
diff -r <tmp-dir-1> <tmp-dir-2>
```

`functions.tsv`, `instructions.tsv`, `transfers.tsv`, `branches.tsv`, `context.tsv`, `relocations.tsv`, `lsda.tsv`, `cases.tsv`, `witnesses.tsv`, `landing-cases.tsv`, `corruption.tsv`, `mutations.tsv`, `branch-mutations.tsv` and `summary.json` are generated. `MANIFEST.sha256` covers these and this README. Addresses in the tables are linked ELF virtual addresses; file offsets are explicitly labeled. FDE ends are exclusive unwind extents, not proof of a complete function census. The linear decode is not a claim that every byte is reachable.

## Evidence

The earlier `staking-stake-accounting-94` packet identifies `delegations.user_to_delegations` at staking state `+0x168` and `delegations.validator_to_state` at `+0x180`. Here `context.tsv` reads the two field-address calculations and calls from the bytes. The same earlier packet identifies the enclosing undelegation path; two additional context windows show its successful outer-row removal results conditionally passed to the shared nested destructor. No enclosing function is selected or reanalysed here.

| Selected role | FDE extent | Bytes | Purpose |
| --- | --- | ---: | --- |
| Nested tree destructor | `0x33f91a0..0x33f94ed` | 845 | Traverse the inner map and release its nodes |
| User-book destructor | `0x33fa7b0..0x33fa87e` | 206 | Obtain outer rows, drop each inner descriptor |
| Validator-member-book destructor | `0x33fbde0..0x33fbeae` | 206 | Same pattern with the other outer row width |
| User remaining-iterator cleanup | `0x3378990..0x33789f2` | 98 | Drop subsequent user-book inner descriptors |
| Member remaining-iterator cleanup | `0x3378360..0x33783c2` | 98 | Drop subsequent member-book inner descriptors |
| Two-book cleanup | `0x37644c0..0x37644fc` | 60 | Drop the first descriptor then the descriptor at `+0x18`; handle the first call's exceptional edge |

For human inspection only, GNU objdump 2.42 shows the normal state cleanup linking the fields to the two selected bodies:

```text
3763d3b: 48 8d bb 68 01 00 00    lea rdi,[rbx+0x168]
3763d42: e8 69 6a c9 ff          call 0x33fa7b0
3763d47: 48 8d bb 80 01 00 00    lea rdi,[rbx+0x180]
3763d4e: e8 8d 80 c9 ff          call 0x33fbde0
```

### Row ownership and normal completion

Both outer functions initialize an iterator from a three-word descriptor. For each returned `(node, index)` pair, the user-book body passes the descriptor at `node + 8 + index * 24` to the nested destructor; the member-book body passes `node + 8 + index * 32`. A null returned node terminates each loop. These offsets are from the selected code; the row names are inherited from the field linkage above. They do not show how the outer iterator finds rows or releases its own nodes.

The nested descriptor contains root, height and remaining-row count in successive eight-byte words. A null root returns without a free, even if the count word is stale. For the selected inner node layout the parent pointer is at `+0`, parent edge index at `+0x1ec`, u16 row count at `+0x1ee`, and child pointers at `+0x1f0`. The selected calls to the boundary in slot `0x576e010` pass size `0x1f0` for a leaf and `0x250` for an internal node, with third argument zero. `relocations.tsv` records its actual ELF relocation; the target allocator is not executed or inferred to be equivalent to the hook.

On the stated finite fixtures, the free-event sequence is left-to-right child-before-parent, each fixture node appears once, and all live node bytes remain unchanged up to the modeled free. `witnesses.tsv` records ordered events with fixture-relative addresses for representative cases. Normal direct calls to the two outer bodies and the two-book cleanup wrapper agree on the same book fixtures. The 201 fixture cases include empty and populated roots, inner trees of heights zero through three, nonuniform row counts, both outer row widths, and residual iterators with previously consumed rows. They also include deliberately noncanonical single-child chains and forks to reach the unrolled eight-level descents. Such chains are control inputs, not evidence of valid on-chain B-trees.

### Exception and corruption boundaries

`lsda.tsv` decodes call-site intervals with the shared ULEB parser. It binds the inner calls at `0x33fa841` and `0x33fbe71` to landing pads `0x33fa863` and `0x33fbe93`, respectively. Each pad calls its remaining-iterator cleanup and then reaches the resume boundary. The first call at `0x37644c7` has landing pad `0x37644df`, which calls the second book cleanup before reaching the resume boundary. The call made during that cleanup has a separate landing at `0x37644f6`. Action numbers and raw records are retained; type-table payloads are not interpreted.

Four controlled interpreter cases inject an exception at the reviewed call instruction, transfer to its LSDA landing, and execute the selected cleanup bytes with checked hooks. Two exercise remaining user/member rows, one exercises the second book after a synthetic first-book failure, and one stops at the second-failure slot. These are injected boundaries: the simulator does not unwind machine frames, execute the target unwinder, or establish effects already performed by a throwing callee. The first injected nested descriptor is null, so no ownership claim is made for a partially destroyed tree.

A null-root/stale-count control returns without a deallocation. A separate synthetic missing-parent control reaches the panic-slot call at `0x33f94e3` after one leaf free. These results describe the modeled malformed inputs only; the actual failure routine and post-panic recovery are not reconstructed. Five targeted byte changes are detected: the null-root condition, size choice, each outer row stride and the second-book offset. These mutations and their detection boundaries are in `mutations.tsv`. Separately, `branch-mutations.tsv` flips each of the 39 conditional opcodes and runs up to two already-passing fixtures that reached the site: 24 changes produced a difference in the checked outputs or free events, 13 reached an interpreter or hook fault, and 2 survived the selected fixtures. A fault is not evidence of the native node's response, and a survivor may be distinguishable on a different input. This is not exhaustive behavioral coverage.

## Implementation and comparison

Independent Rust: **not yet implemented**. Cargo build scope, compiler and linker flags, two-build results, raw and normalized compiled-code comparisons, normalization masks, native allocator and unwinder behavior, relocation-target closure and whole-ELF identity are **not yet implemented/measured**. The interpreter's independent fixture oracle compares node release order, release size, third argument and unchanged bytes; the two outer iterators supply checked synthetic row sequences and their internal traversal and outer-node frees are not executed. No target binary, chain, key or network operation is used.

## Results and limitations

- The selected denominator is 6 FDE-described extents totaling 1,513 bytes and 383 linearly decoded rows. Of these rows, 372 were reached in at least one normal, synthetic-corruption or injected-landing fixture. Of 39 conditional sites, 34 saw both outgoing edges; none was wholly unreached. Deep noncanonical controls contribute to these counts; they do not establish live-state reachability.
- The generator checks 201 fixture cases, including 34 explicitly labeled noncanonical shapes, 4 injected landing cases, 2 corruption controls, 5 targeted mutations and the 39-branch mutation sweep. The focused suite passes 29 tests with zero skips. The LSDA output has 16 call-site records, with 4 selected extents carrying LSDA data.
- Iterator ordering, freeing of outer nodes, actual allocation and exception routines, action-table payloads, arbitrary malformed structures, and mutation after a real partial failure are outside this result. There is no native differential run or independent Rust implementation. Stake accounting and epoch transitions across #94 and #115 remain open; this packet requests no progress gate.

Next question: independently reconstruct the two outer iterator ownership contracts and validate partial inner-drop failure against an authorized isolated target-grounded harness.
