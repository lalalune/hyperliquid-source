# RE-006: node #115 TWAP advance step, from the user lookup to the heap push or the finish hand-off

This packet rebuilds, and proves on the bytes of node #115, what happens to a due TWAP record after its slice has been handed on: the tracker looks the user up (and adds an empty user record when it is missing), the order ring is searched, the due moment moves 30 s on and is caught up past the clock in whole 30 s steps, the step counter saturates upward, and the order is either pushed back on the heap as a 0x28-byte entry or handed to a finish callee. A Rust node can now take the reschedule rule, the finish rule, the date-failure fallback and the 64-user ring limit from one checked specification instead of from the node #94 reading.

- Component ID: orderbook (work item RE-006)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace commit `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; the deleted node #94 packet `RE-006-twap-slice-94` (git history before the migration commit `8fd8db680`) is used only as a lead for the rule list, every address, offset and rule below is re-derived from node #115 bytes, and the differences are listed
- Claim status: observation for every row the evaluator ran against the bytes; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: the four advance bodies `0x5a145d0`, `0x5a13910` (perp) and `0x5a13f70`, `0x5a14c30` (spot) from the first byte to the return, run as real code; the tracker entry helpers `0x4dc5ad0` (perp) and `0x4dc2040` (spot) and the entry resolvers `0x4da6d70` and `0x4da7360`, run as real code; both user-ring arms of the helpers; the 64-user promotion limit as a boundary
- Scope excluded: the four finish callees `0x5a17dd0`, `0x5a18190`, `0x5a18550`, `0x5a18840` (stubbed, arguments checked); the heap push `0x4ecb990`; the order and user ring searches `0x57f36b0` and `0x57f4ac0`; the ring insert helpers `0x57ecf00` and `0x57ea4b0`; the B-tree arms of the tracker containers (tag `0x8000000000000000`); the chrono helpers behind the slots `0x64e0f78`, `0x64e0aa0`, `0x64e0fc0`, `0x64e0f70` and libm ceil behind `0x64e7858`
- Related work: the slice step that calls these bodies is the merged/open node #115 `RE-006-twap-slice-115` packet, which stubs `advance`; this packet runs the four callees it stubbed. The node #94 advance rule list is not reused as a fact.

## Reproduce

Run from the repository root with Python 3 and the standard library; the shared `tools/elf_index.py` and `tools/fde_extents.py` parse the ELF. No external program runs, the binary is never executed, and nothing touches a network. The tool refuses any other digest. One full run takes a few minutes and stays well under 1 GB.

```
python3 tools/twap_advance_115.py --out research/work-items/RE-006-twap-advance-115
python3 -m unittest tests.test_twap_advance_115
```

The committed files were produced with the default options (3000 random cases per body, every third case written to `cases.tsv`, 60 branch flips per representative body). `MANIFEST.sha256` lists every file in this folder except itself.

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`; function bounds are FDE bounds from the shared parser (`copies.tsv`). Every table is generated from the bytes or from a run of the real instructions.

### Observations: the call shape

`callees.tsv` lists, per body, the entry helper, entry resolver and finish callee. The four bodies are 1,625 bytes and 365 instructions each. The two perp bodies differ from each other only in the finish callee; the two spot bodies likewise; perp and spot differ only in the helper pair and the finish callee (`copy_differences.tsv`, 5 rows, all `call target`). Slots used for indirect calls are read from the instruction bytes and resolved through `.rela.dyn` relative relocations, so the same four chrono slots, ceil slot and conversion slot serve all four bodies (`stubs.tsv`).

### Observations: the rule, in order

1. Entry helper `0x4dc5ad0`/`0x4dc2040` on `tracker + 0x18` (a 4-word ring header: capacity, buffer, head, length; user records are 0x38 bytes, the order ring header sits at record `+0x18`). If the ring is already a tree (capacity word `0x8000000000000000`) with fewer than 0x20 users it is converted back to a ring. Otherwise `0x57f4ac0` searches the 20-byte user key.
2. If the user is absent and the ring already holds more than 0x3f users, the ring is moved out and handed to the promotion `0x515a060`/`0x51581b0`, so a 64th user turns the ring into a tree. The tool treats that call as a boundary and checks the stop and the exact length at which it happens (63 users: no promotion; 64: promotion).
3. Resolver `0x4da6d70`/`0x4da7360`: an occupied entry returns the record's order-ring address. A vacant entry builds a record whose key is the user and whose container is empty (words 0, 8, 0, 0), calls the ring insert `0x57ecf00`/`0x57ea4b0` at the searched position, and returns the new record. So an advance on an unknown user adds an empty user record to the tracker and then finds no order (`user inserted` outcomes).
4. `0x57f36b0` searches the order ring by order id. Absent, or a position at or past the ring length: return with no write. Otherwise the order is the 0x70-byte slot at `buffer + physical * 0x70`, body from `+8`.
5. The due moment (12 bytes at body `+0x48`: packed date, seconds, nanos) moves on by 30 s through the chrono time add. The carried whole seconds go through two range tests (`CARRY_*` immediates, pinned in `constants.tsv`); out of range, or a failed date add, the node uses the 12-byte moment stored at `0x4679d0` (`2147473118, 86399, 999999999`) instead of panicking. This replaces the assertion/expect of the node #94 reading.
6. The new moment is compared with now (`outer + 0x60`, 12 bytes): signed packed date, then unsigned seconds, then unsigned nanos. Equal is not late. When late, `now - moment` becomes an f64 (nanos fixed up when seconds are negative), negatives clamp to 0, the quotient by 30 is rounded up by ceil, times 30 gives the catch-up seconds, they go through the f64-to-duration slot, are capped at `i64::MAX` nanoseconds, split again and added through the time add and the same two range tests. A negative or NaN gap does not assert; it counts as 0.
7. Counter at body `+0x40` is increased with saturation at `u64::MAX` and stored; the due moment is stored at body `+0x48`. Both are stored before the finish test.
8. Finish when `executed (+0x30) >= total (+8)`, or when the counter exceeds `2 * saturate(duration / 60) + 1` (saturate: NaN, infinities and negatives give 0, above `u64::MAX` it caps; the `+1` and the doubling saturate). Finish: callee gets the tracker, the user key, the order id, a pointer to the word `0x8000000000000002` and the output vector in `r9`. Otherwise the heap push gets `tracker` and the 0x28-byte entry `order id (8) | moment (12) | user (20)`.

### How it was run

`copies.tsv` lists the stepped instructions per function: each advance body 322 of 365, each entry helper 71 of 250 (the tree arms are boundary), each resolver 48 of 80. The harness fills the tracker ring, the user ring buffer and the order ring with position-dependent filler, so a wrong ring offset shows. Stub calls are recorded in order with their arguments; the specification (`spec_advance`) is separate code that predicts the whole event list, the order record and the user ring afterwards. 12148 cases (4 bodies x (37 named + 3000 random)) all match. `outcomes.tsv` counts finish, reschedule, none, user inserted and stop per body.

## Implementation and comparison

Rust implementation: not yet implemented. The comparison model is `spec_advance` in `tools/twap_advance_115.py`; the chrono helpers are stubbed with the stated contracts (time add with carry, date add as packed ordinal arithmetic, time difference with floor nanos), the same functions drive the stubs and the specification, so the packet proves the control flow, the field offsets and the arithmetic of the bodies, not the chrono helpers.

Negative controls (90 counted, 90 detected):
- 12 wrong specifications (`variants.tsv`): added step 31, no user insert, no carry range test, panic on date failure (the node #94 rule), catch-up at equal, unsigned date compare, floor instead of ceil, wrapping counter, finish above not at total, steps without the `+1`, finish at the step count, other entry layout. Each disagrees with the bytes on at least 45 cases.
- 80 conditional-branch flips on the bytes of the representative perp and spot bodies and their helpers, reached by the cases; 70 are detected (`mutants.tsv`), 10 survive and are not counted as controls. The survivors are all branches of the f64 sign/exponent classification of the catch-up quotient (`0x5a14907`, `0x5a14aa8`, `0x5a14ab5`, `0x5a14b7c`, `0x5a14b89` and the spot copies); they are not claimed equivalent, a case pool with infinite or denormal gaps could kill them.
- 4 structural refusals (wrong digest, address outside every FDE, not an FDE start, inside another body) and 4 byte pins of the range-test immediates that each fail on a one-byte corruption.

## Results and limitations

- 12148 cases, 0 mismatches on the first full run; 90 of 90 negative controls detected; mutants 10 survive (listed, not counted).
- New against the node #94 reading (all re-derived on node #115): unknown user is added empty; failed date add or carry out of range uses the stored moment instead of panicking; no assertion on a negative or NaN gap; a ring of 64 users is promoted; the finish word and the entry layout are the ones above.
- Limits: the tree arms of the tracker containers and the order lookups in tree form are not run; chrono, ceil and duration conversion are contracts, not code; the finish callees, the heap push and the ring searches are stubs with checked arguments; the generated users keep rings small, so cases with a full ring and a non-trivial wrap use capacity at most 9. The packet does not claim the orderbook gate or any component gate.
- Next question: the four finish callees `0x5a17dd0`, `0x5a18190`, `0x5a18550`, `0x5a18840` (955 and 750 bytes; they call `0x44e0810`, `0x5181da0`/`0x51821b0`, `0x5182b60`/`0x5182640`, `0x5a10250`/`0x5a10560`, `0x5a3e1d0`/`0x5a40ae0`, `0x5a4a6f0`), then the heap push `0x4ecb990` and the drains that call these bodies.
