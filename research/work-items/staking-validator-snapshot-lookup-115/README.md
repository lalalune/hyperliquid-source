# staking: recover the node #115 validator snapshot lookup, its ring and B-tree stores, and the status drop of its two failures

This packet makes it possible to write the validator-membership test that the signer admission gate reaches through slot `0x64e4e38` (body `0x36c8430`) from bytes: the lookup keeps one snapshot of 20-byte addresses per epoch word in a store that is either a sorted ring of 0x38-byte elements or a B-tree keyed by u64, matches the epoch exactly (no nearest-lower rule, no 32-bit truncation), keeps each snapshot as either a ring of 0x68-byte elements or a B-tree with 32-byte keys and 0x48-byte values, compares the signer over all 20 bytes, scans every element without an early exit, returns 1 with no side effect when the signer is a member, and otherwise returns 0 after dropping status `0x9b` (no snapshot for the epoch) or `0x2b` (snapshot without the signer) through the status drop `0x36dae30`, whose jump tables are decoded for every word below `0x200`. The lookup, the ring search `0x4551810`, the B-tree iterator step `0x37c5530` and the status drop run as real bytes in an interpreter inside the tool and agree with a separately written rule list on 19,259 constructed cases with 0 mismatches; 172 of 172 negative controls are detected.

- Component ID: staking (Staking and validator lifecycle); first task: validator membership for signed actions. The packet requests no gate.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6` / the reference is not used for any claim here.
- Claim status: observation for everything under Evidence (ELF bytes, run by the interpreter of this tool); lines marked inference are not proved; unresolved items are under limitations.
- Scope included (real bytes): the lookup `0x36c8430`, the ring epoch search `0x4551810`, the B-tree iterator step `0x37c5530` and the status drop `0x36dae30` (jump tables `0x79b9c0` and `0x79bc30`, compare ladder, second-level tables). Only the free routine behind slot `0x64df4a0` and the three panic slots `0x64df620`, `0x64df4c0`, `0x64df830` are replaced by recording hooks.
- Excluded and why: the callers (the admission gate copies reach the lookup through the slot; they are the subject of the separate draft packet `staking-admission-gate-115`, whose lookup stub this packet replaces by bytes), the writers that build or rotate the snapshot store, and the meaning of the other fields of the 0x68-byte ring element and of the 0x48-byte tree value. No #94 address is used.

## Reproduce

From the repository root, with Python 3 and the standard library only (no external program is started, the binary is never executed, the tool reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py` and checks the input SHA-256 first):

```
python3 tools/staking_validator_snapshot115.py --out research/work-items/staking-validator-snapshot-lookup-115
python3 -m unittest tests.test_staking_validator_snapshot115
```

Generated files: `evidence.json`, `measure.json`, `path.tsv`, `function-rows.tsv`, `constants.tsv`, `layouts.tsv`, `scenarios.tsv`, `status-drop.tsv`, `mutations.tsv`, `controls.tsv`. `MANIFEST.sha256` covers them and this README. Two regenerations into different folders are byte equal.

## Evidence

All addresses are virtual addresses of the ELF; function bounds come from the FDEs; slot targets come from `.rela.dyn` RELATIVE rows. `function-rows.tsv` holds the 513 reached instructions of the four real bodies with their bytes, `constants.tsv` every reached immediate, `path.tsv` the body size and the reached part of each function, `layouts.tsv` the field offsets used by the fixture.

### Lookup `0x36c8430` (rdi = store, rsi = pointer to the 20-byte signer, returns al)

1. The epoch word `[store+0x58]` is copied to the stack. A first word `[store]` equal to `0x8000000000000000` selects the B-tree store, any other value is the ring capacity.
2. Ring store: capacity `[+0]`, buffer `[+8]`, head `[+0x10]`, length `[+0x18]`. `0x4551810(store, &epoch)` returns al = 0 and the logical index of an equal epoch, or al = 1. A miss, or an index at or past the length, writes `0x9b` to a stack record, zero to its second word and calls the drop. A hit takes the physical slot `index + head`, minus the capacity when that reaches it, and the snapshot value at `buffer + slot * 0x38 + 8`.
3. B-tree store: root `[+8]`, height `[+0x10]`. A node has its length as a u16 at `+0x272`, u64 keys at `+0x218` and edges at `+0x278`; the scan continues while the epoch is above the key, an equal key gives the 0x30-byte value at `node + 0x30 * index`, otherwise the walk descends through the edge or, with the height used up, drops `0x9b`.
4. The 0x30-byte snapshot value: `[+0] == 0x8000000000000000` selects a B-tree (root `[+8]`, height `[+0x10]`, length `[+0x18]`) that is walked in order with `0x37c5530`; any other value is a ring (capacity, buffer, head, length) of 0x68-byte elements walked as two slices. An empty ring or tree walks nothing.
5. Every element's 20 bytes are compared as 16 bytes plus a dword (`pcmpeqb`, `pand`, `pmovmskb == 0xffff`) and the results are OR-ed. The ring element holds the address at `+0x40`, the tree value at `+0x20` (keys are 32 bytes at node `+0`, values 0x48 bytes at `+0x168`, parent `+0x160`, parent index `+0x480`, length `+0x482`, edges `+0x488`). The walk always runs to the end: the OR is read after the loop.
6. No member: stack word `0x2b`, call the drop, return 0. Member: return 1, no drop. The argument is never written (checked on every run).

### Ring epoch search `0x4551810`

A binary search over the two slices of the ring (element 0x38 bytes, key u64 first). The first element of the buffer decides which slice holds the epoch when the ring wraps. It returns al = 0 and the logical index on a hit, al = 1 and the insertion index on a miss. `ring_exhaustive` runs every ring of 1 to 7 elements with 0 to 2 spare slots, every head and every epoch around the elements (1113 cases).

### B-tree iterator step `0x37c5530`

State words: front tag `+0` (must be 1 while items remain, else the panic slot `0x64df830` is called), front node `+8`, root or height `+0x10`, index `+0x18`, remaining count `+0x40`. The first call descends along edge 0 from the root (loops unrolled by 8 once the height reaches 8), later calls climb through parent and parent index when the node is exhausted, and the count reaches zero with a null return. `tree_iter` and `tree_deep` run trees of 0 to 600 entries and forced heights 2 to 9.

### Status drop `0x36dae30`

The drop reads a u16 word and dispatches: words up to `0xef` through the table `0x79b9c0` at index `word - 0x3d` (0 to `0x9b`), words `0xf0` to `0x15f` through the table `0x79bc30` at index `word - 0xf0` (0 to `0x19`), `0x160`, `0x16f`, `0x17d`, `0x188` through a compare ladder, everything else straight to the return `0x36dafea`. The tool computes the expected arm of each of the `0x200` words from the table bytes and requires the interpreter to enter it, under 10 payload shapes (`status_drop`, 5,120 cases). `status-drop.tsv` lists the 24 words that have an arm of their own (9 distinct arms; the rest return at once). The two lookup statuses `0x2b` and `0x9b` both return at once and free nothing. Payload-owning arms free through slot `0x64df4a0` (the `free_sizes` column of `status-drop.tsv` is the payload qword that the arm passed as the size; the fixture's owned qword is `0x600100800`): words 0x3d, 0x3e, 0x52, 0x68, 0x86, 0x87, 0xbd, 0xc1, 0xc2, 0xc7, 0xc8, 0xd7, 0xd8, 0xf0, 0x105, 0x107, 0x109, 0x16f, 0x17d, 0x188 free with an owned payload. 5 of the 48 listed runs end in an interpreter halt because the payload pointer leads outside the fixture; they are recorded as `halt`, not claimed.

## Implementation and comparison

The tool `tools/staking_validator_snapshot115.py` is the implementation: a concrete x86-64 interpreter that decodes only forms present in these bytes and raises on anything else, plus a rule list (`spec_lookup`, `spec_search`, `spec_iter`, `drop_arm`) written from the reading above, not from interpreter output. A fixture builder lays out ring buffers with any head and spare capacity, and B-trees of any height in the two node layouts (balanced by a deterministic builder, fan-out chosen per node). Each case runs the real bytes and compares the result byte, the ordered record of drops and frees, the iterator output or the entered arm with the rule list. Reference comparison: not performed.

## Results and limitations

- 19,259 cases, 0 mismatches on the first full run of the final tool: lookup 3402 (member 422, status `0x2b` 973, status `0x9b` 2007; both stores, both value forms, rings with and without wrap, snapshot counts 0 to 60, tree values up to 200 entries, epochs above and below 2^40, an epoch that equals a snapshot epoch plus 2^32), form pairs 8000 (4,000 random worlds, each run once as built and once in the other store forms: ring and tree outside, vec and tree inside, which must give the same result and drops), ring search 900, ring exhaustive 1113, iterator 724, status drop 5120.
- 172 negative controls, 172 detected: moved layout fields of the fixture (a wrong offset must disagree with the bytes), 12 deliberately wrong rule lists (nearest-lower epoch, any snapshot, 16-byte compare, drop codes swapped, 32-bit epoch, early stop and others), 141 single-byte edits of the real code (condition flips and immediates) and out-of-range inputs (wrong digest, address inside a function, address outside every FDE or section, an iterator in state 2, an arena that is too small, a step limit of 20, a rule list asked about another signer).
- Byte edits: 164 possible, 141 killed, 23 survived (iterator step 2, ring search 2, status drop 14, validator lookup 5). Read as redundant or equivalent: the first tag compare `0x36c860b` (the second compare then catches the same tag), the tag compares `0x36c8618` and `0x36c86af` that no ring-walk path reaches, the unused back-cursor store `0x36c85f0`, the unroll bounds `0x37c55b5` and `0x37c5698` and the bisection bounds `0x4551865` and `0x45518d5` (both sides of the bound compute the same result), and range-bound immediates of the status drop next to words that have no arm (status-drop edits are detected only against the baseline run of the unedited bytes, not against an independent model). The other survivors, among them `0x36c8472`, are not classified.
- Fixture limits: the B-trees come from this tool's builder, not from a captured node; the walk reads only the fields listed in `layouts.tsv`, so the other bytes of the 0x68 and 0x48 byte records are filler. The parent-index field of the outer tree is never read by the descent, so moving it is not a control.
- The meaning of the store (a history of validator address sets by epoch or round) is inference from the shape; the writer of the store, the source of the epoch word `[store+0x58]` and the other fields of the elements are not read here.
- The free routine behind `0x64df4a0` and the panic slots are hooks; the arms of the status drop other than the two lookup statuses are not interpreted beyond which payload shapes free.

Next question: who builds and rotates the snapshot store (writer of the ring and the B-tree form) and what fills the epoch word at `+0x58`.
