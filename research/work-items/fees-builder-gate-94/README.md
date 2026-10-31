# fees: node #94 builder fee admission in the order parsers

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for byte-derived rules below, inference where marked, unresolved items listed under Results and limitations
- Scope included and excluded: included are the gate that decides whether an order action may carry a builder fee, in 6 parser copies, plus the steps that run before and after it in those parsers. Excluded are the row parser, the grouping validator body, the notional and delegation helpers (all stubs that check their arguments), the builder charge at fill time, and how the approval rows are written.

## Reproduce

Run from the repository root:

```
python3 tools/fees_builder_gate.py --out research/work-items/fees-builder-gate-94
cd research/work-items/fees-builder-gate-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_builder_gate
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`; a table decoder inside the tool must land exactly on every FDE end. A full run took 750 s on 3 worker processes (`WORKERS` in the tool) and writes `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv` and `reference-diff.tsv`. The outputs are the same across runs and do not depend on a binutils version.

## Evidence

Coordinates are virtual addresses in the ELF above. The objdump lines below are a reading aid from a human session. They are not part of the generated files, which come from bytes alone.

### Boundaries

- 0x1ea3140: FDE 0x10505dc, end 0x1ea3f55, 711 instructions decoded, 664 executed
- 0x1ea3f60: FDE 0x1050630, end 0x1ea4caf, 653 instructions decoded, 567 executed
- 0x284b9f0: FDE 0xd90ba4, end 0x284baca, 62 instructions decoded, 61 executed
- 0x36f3ed0: FDE 0xe4b148, end 0x36f3fd1, 70 instructions decoded, 70 executed
- 0x4322ca0: FDE 0x122e60c, end 0x4323b3e, 736 instructions decoded, 682 executed
- 0x4323b40: FDE 0x122e660, end 0x432488f, 653 instructions decoded, 567 executed
- 0x4324890: FDE 0x122e6b4, end 0x43255df, 653 instructions decoded, 567 executed
- 0x43255e0: FDE 0x122e708, end 0x432647e, 736 instructions decoded, 682 executed
- 0x4927d70: FDE 0xf186a4, end 0x4927e4a, 62 instructions decoded, 61 executed

All 9 bodies are decoded to their FDE ends and interpreted on the vectors. `evidence.json` holds the call sites of each function (`callers`). Copies differ only in shape: two use exchange state fields shifted by +0xa80 (`state_shift`), and helper addresses differ.

### The gate

At 0x1ea3a2e in the perp-like parser 0x1ea3140, reached only when bit 0 of action byte +0 is set:

```
1ea3a26: mov    r12,QWORD PTR [rsp+0xc8]       ; copy of action +8
1ea3a2e: mov    bp,0x129
1ea3a32: cmp    r12,0x64
1ea3a36: ja     1ea3e06
1ea3a3c: mov    bp,0x128
1ea3a40: cmp    QWORD PTR [r13+0x6a8],0x0
1ea3a48: je     1ea3e06
...                                            ; probe of table +0x690, row stride 0xe8
1ea3b2c: test   r12,r12
1ea3b2f: je     1ea3b58
1ea3b39: lea    rdi,[rcx+r9*1]
1ea3b3d: add    rdi,0xffffffffffffffb0         ; row +0x98
1ea3b41: call   284b9f0
1ea3b46: test   rax,rax
1ea3b49: je     1ea3e06
1ea3b4f: cmp    r12,QWORD PTR [rax]
1ea3b52: ja     1ea3e06
```

Observed rule, with `rate` = action +8 (u64), `builder` = 20 bytes at action +0x10, `who` = the master of the user or the user itself:

1. Bit 0 of action +0 clear: no builder check at all, for any rate. A value of 2 counts as clear.
2. `rate > cap`: status 0x129 "Builder fee is too high." The cap is 100 in the three perp-like parsers and 1000 in the three spot parsers. The rate equal to the cap passes.
3. Table at exchange state +0x690 empty, or no row for `who`: status 0x128 "Builder fee has not been approved." This holds at rate 0 as well.
4. Rate 0 with a row: admitted without reading the row tree, so an empty tree or a tree holding only other builders passes.
5. Rate above 0: the B-tree at row +0x98 is searched for `builder` (key 20 bytes, value u64). No entry or `rate > value`: 0x128. `rate == value` passes.

The cap test runs first, so a rate over the cap with no row reports 0x129.

`who` comes from table +0x3810 (key 20-byte user, stride 0x28): a hit gives the stored address, a miss or an empty table gives the user. The spot parsers call 0x36f3ed0 through slot 0x5773220, the perp-like parsers carry the same probe inline.

### Order of the steps

Perp-like: grouping and row collection, then row conversion (a row error stops there), then index above 100000000 with kind 3 gives 0xb2, an empty list gives 0x6a, then the builder gate, then the kind 3 amount test when the index is not 0 (0xb4), then the grouping rules of kinds 1 and 2 (0x6b to 0x70). Spot adds a refusal after the empty test: kinds 1 and 2 give 0xf5 with "TP/SL", any non-limit row gives 0xf5 with "Placing trigger orders". `vectors.tsv` lists every outcome.

An accepted action keeps the first 0x28 bytes of the action in the result, which carries the rate and builder to later stages (result +8, compared whole by the evaluator).

No parser writes state on any path: the evaluator compares the exchange state, tables, action, rows and user bytes after every run.

### Census

Byte scan of `.text` for `mov r16, 0x129` followed within 24 bytes by `mov r16, 0x128` gives exactly the 6 functions above with the caps above, read from the compare immediate (`gate_pairs`). One more 0x129 hit, 0x44d21ae, has no paired tag (`tag_hits_without_a_pair`) and may sit inside another instruction; it was not read.

### Inferences (not proved by these bytes)

- `rate` looks like a builder fee rate in tenths of a basis point, so the caps would read as 0.1% and 1%. The bytes prove only the compare against 100 and 1000 and the compare against a per-builder approved value.
- Table +0x690 has stride 0xe8 and its row tree sits at row +0x98; earlier fee work names +0x5d0 + 0xc0 as `user_states` of the fee tracker. Same offset, so same table by inference. Row +0x98 would be the map a user fills by approving a builder.
- Table +0x3810 maps a sub-account or agent to the master. Reference naming only.

### Reference comparison

`reference-diff.tsv` compares `references/can1357-hl/l1/exchange/handlers/14_order.rs` row by row: 9 rows, 2 same, 7 differ. The main difference is that the reference reads the 100 and 1000 compares as an order count limit; the bytes compare action +8 while the order count is action +0x38, and tag 0x129 prints "Builder fee is too high."

## Implementation and comparison

No Rust implementation: not yet implemented. Comparison here is between decoded bytes and a separate closed-form Python model (`model` and `builder_rule`).

The evaluator interprets the real instructions of the listed functions over strict memory arenas: a read of an unset byte of a table or action is a fault. Stubs for called helpers check their arguments, spoil caller-saved registers and write position-dependent byte patterns, so copied bytes can be followed. Real hashbrown layouts with probe walls and deleted slots, and real B-tree node layouts up to height 9, are built by the tool.

## Results and limitations

- Vectors: 5010 across 6 parsers, 0 mismatches. Outcomes by status are in `evidence.json` (`outcomes`).
- Instructions: 3921 of 4336 decoded instructions executed; the rest are listed in `evidence.json` (`unexecuted`, with reasons) or padding, and the tool fails on any other unexecuted instruction.
- Mutation survey: 334 mutants of every conditional, field displacement and immediate in the gate range of the two main parsers, the B-tree lookup and the master lookup; 325 killed, 9 equivalent with a reason each in `mutations.tsv`. The other 4 parsers were not mutated; they run all vectors.
- Corruption controls in the tests: wrong digest, address outside the image, address without an FDE, cap byte changes, flipped compares, a wrong tree stride, a decoder end off by one. Unit tests: 28.

Limits:

- Spot arms for kinds 1 and 2 past the jump table are unreachable as far as these parsers go: the kind test at 0x1ea448e stops both first (`unexecuted`, `DEAD_ARM`).
- Unwind and capacity panic paths are not modelled.
- Whether a real caller ever passes byte +0 above 1 is unknown; flag 2 is a control for the bit test.
- Which text path produced `rate` was not traced here.

Next question: which fill-time code reads the rate and builder carried in the result at +8, and does it apply the same unit as the 100 and 1000 caps?
