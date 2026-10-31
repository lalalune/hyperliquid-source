# RE-008: node #94 client block path of a non-validator: round gate, tx join, buffer, batch verify and commit proof

This packet shows the exact rule by which a node #94 non-validator accepts blocks from a peer and hands them to its local channel, so the Rust node can write `nv_stream` verification from a rule list and not from the reference stub: blocks wait in a vector of at most 100 until one arrives with a commit proof, then the whole batch passes in order (QC round and QC hash link each block to the one before, tx bytes hash to the block's hash list, 12 byte time equal) and the proof must hold a child of the last block, a QC over that child, and child round == last round + 1. It settles what the reference calls `execution_marker` and `parent_round` (a commit proof and the QC round) and how a first gap differs from a later gap.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference labels are leads only, nothing is copied
- Claim status: observation for every row marked as run or pinned; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: `0x4548050`, `0x4360000`, `0x4547690`, `0x454ee00`, `0x44c6e70` run for real from their first byte, and the round gate rows of the forward poll `0x4759970` from `0x475a3aa`; the seven call sites of `0x4360000` and the one of `0x4547690`
- Scope excluded: the rest of the three forward polls, the stream decode before the join, the reconnect after an error, the channel reader, the body of `0x454b700`, `0x4758d70` and `0x454c050` (run in the block admission packet), and the peer choice
- Related work: #338 (`nv-stream-inventory-94`) lists these functions, Locations and call edges and states no rule for them; this packet starts where its next question points. #282 (`RE-008-consensus-error-tags-94`) maps tags to variant names from formatter tables and raises no row; `error-tags.tsv` here says which row raises each one and under what condition, and every name is pinned from bytes. #588 binds the window arithmetic of the bootstrap loop `0x4389070`, which this packet only lists as a caller. #499 and #154 use `0x439baf0` for other questions. RE-008-commit-walk (open #951) is the same two link rule on the validator side and RE-008-block-admission is where `0x454b700` and `0x4758d70` are run.

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes about 15 s.

```
python3 tools/client_block_batch_path.py --out research/work-items/RE-008-client-block-batch-94
python3 -m unittest tests.test_client_block_batch_path
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`. Function bounds are FDE bounds from the shared parser. Every table is generated from bytes or from a run of the real rows.

### Observations: where it runs

`callers.tsv` comes from a byte scan of every `ff 15` and `ff 25` rip relative row in `.text`. Only slot `0x5776668` holds `0x4360000`, and seven rows read it: one in the bootstrap loop `0x4389070` and two in each of the three poll copies `0x439baf0`, `0x4759970`, `0x4b3c880`. `0x4547690` has one call site, `0x436016b`, and no relocation holds it. The Location at `0x436039e` is `node/src/nv_stream.rs:262:21`.

### Observations: the rule

`gates.tsv` has 36 ordered rows, each with its site and case count. In order:

Round gate in the poll, on the block's QC round against `state+0x108` (named `self.last_recv_round` in the text at `0x1e2cfb`):

1. Under it: warning `received old client block, is peer behind?`, the block is dropped, the result is success. The rule reads the QC round, so a block with a high round and a low QC round is old.
2. Equal: `state+0x118` (`self.bootstrapped`) is set to 1 and the buffer runs.
3. Over it with `bootstrapped` set: `unexpected client block round`, outer tag `0x2c`.
4. Over it with `bootstrapped` clear: a `node_bootstrap` future for rounds `last_recv_round + 1` (saturating) to the QC round, with 300.0 at `+0xfc0`. `bootstrapped` stays clear. So only a gap seen before the first in-order block starts a catch up.

Tx join `0x4548050`, before the gate:

5. A row list already present passes through with no lookup.
6. Otherwise each block hash in order is looked up in the local tx map (one or two levels run here), its tx Arc cloned, repeats kept. The first miss gives tag `0x1c` with that hash, and the built rows and the block Arc are dropped.
7. Rows go to a new Arc. The bytes from the map still face the tx hash rule below.

Buffer `0x4360000`:

8. QC round must equal `state+0x108`, else outer tag `0x2c` with the QC round and both Arcs dropped. The poll compares first, so of the callers only `0x4389070` can reach this row.
9. `state+0x108` takes the block round before any check of the block, and the row is pushed.
10. No proof (word at block `+0x108` is `0x8000000000000000`): length up to 100 is success, 101 gives the owned text `Too many unconfirmed blocks` and pending stays as it is. A block with a proof is verified however long pending is.
11. With a proof: the mutex at `state+0xf0` is taken and the whole pending vector goes to `0x4547690` with `state+0x110` as start round. So a proof always ends a batch, on any block.
12. Failure: warning `failed to verify client block batch: `, unlock, the error goes back unchanged. Pending and the advanced `state+0x108` stay.
13. Success: `state+0x110 = state+0x108`, pending is taken and replaced by an empty vector, and each row goes to the channel at `state+0xc8` in order. A closed channel (word `+0x1c0` bit 0) drops that row and the rest, prints `client block send failed: ` and gives outer tag `0x35`; `state+0x110` keeps its new value. A waker at `+0x100` fires once.

Batch `0x4547690`, for each block in order:

14. Proof only on the last block (tag `0x1a`). QC round == previous round, the start round for the first block (tag `0x15`). From the second block on, QC hash == digest of the previous block (tag `0x16`). The first block has no hash check at all.
15. `0x454b700` on the block, error unchanged. This is the same call that block admission makes.
16. Each tx row: Keccak-256 of the tx bytes (rate `0x88` at `0x454784e`, delimiter 1 at `0x454785a`) == row hash (tag `0x17`). Row count == block hash count, row hashes == block hashes in order (tag `0x18`). The 12 byte time equals block `+0x90` word by word (tag `0x19`).
17. There is no rule that rounds move by 1 inside a batch: a batch with gaps passes.

Commit proof, after the last block, which must have one (tag `0x1b`):

18. Digest of the last block. `0x454b700` on the child at block `+0x108`. `0x4758d70` on the QC at block `+0x200`.
19. QC hash inside the child == digest of the last block (tag `0x1d`).
20. Hash of the `+0x200` QC == digest of the child (tag `0x1e`). On this failure a clock read `0x14385c0` and a second digest of the child happen and are unused.
21. Child round == last round + 1, saturating at u64 max (tag `0x1f`). The round inside the `+0x200` QC and the QC round inside the child are not read.

Tags `0x1a` and `0x1b` are not reachable from `0x4360000`: rule 11 calls the verifier only on a proof block, and that block is last. They are run on the verifier alone.

### Observations: layouts and tags

`layouts.tsv` has item, client block Arc, tx row, local map node and stream state rows, each with a reading site. `error-tags.tsv` gives each tag, the raising row, the variant name, the address of that name and the case count. `outer-tags.tsv` lists the buffer's own tags `0x2a` (text), `0x2c`, `0x35`, `0x40` (success). Strings and two Locations are in `strings.tsv` and `locations.tsv`.

### How it was run

`functions.tsv` lists the functions: 4320 of 5020 bytes reached in the five whole ones, and 603 bytes of the poll, which runs only from `0x475a3aa` to its exits. The rows run under an x86-64 row evaluator in the tool over real Arc, vector and B-tree bytes at the layouts the code reads. `stubs.tsv` names every edge. `spec_run` is a separate rule list with no instruction rows. It predicts each step's result and payload, the ordered trace of checks, digests, sends, logs, Arc drops and lock paths, `last_recv_round`, the confirmed round, `bootstrapped`, pending, Arc counts and channel words. 479 cases, 79 named and 400 vectors, all match; `cases.tsv` holds each one and `outcomes.tsv` the totals.

### Inferences, kept apart

- Tag to variant name is taken from #282's formatter tables. The names fit every row here, field keys included (`round, expected` and `hash, expected`), but this packet does not rerun the formatter dispatch.
- Reading the proof as "child plus QC over the child" is the variant names `CommitProofChildQc`, `CommitProofGrandchildQc` and `CommitProofConsecutive` plus rows 19 to 21. Calling it the same two link commit rule as `0x44ab970` is an inference from the shape.
- Reading the 12 bytes as a chrono time rests on the size, the name `ClientBlockTime`, and the clock stub layout used elsewhere; the rows only compare words.
- Reading the item as coming from a peer stream rests on the strings and on `nv_stream.rs`; the decode is not read.
- The confirmed round at `state+0x110` is named here from its use. No string names it.

### Differences from the reference

- `node/nv_stream.rs` has `ChainContinuityVerifier`, a stub that skips the tx rows, the time, the signature, the QC and the proof. The rows above replace it.
- It names block `+0x108` `execution_marker` and says the path waits for "execution-state material". The bytes read a child block and a QC there, and no execution state is read.
- It names block `+0x50` `parent_round` and `+0x58` `hash`. They are the QC round and QC hash, read by `0x4547690` with the QC offsets of `0x4758d70`.
- Its old block rule is `packet.round <= state.confirmed_round`. The bytes compare the QC round with `last_recv_round`.
- It reads the 12 byte time as a set of counters passed to the verifier. They are a compare against block `+0x90`.

## Implementation and comparison

Rust implementation: not yet implemented. `spec_run` in the tool is the comparison model. Original rows against the rule list: 479 of 479 equal, compared on the observations listed above. Controls: `pins.tsv` 75 byte rows, 12 relocation slots, 20 strings, 2 Locations, byte scans for both caller sets, each with a negative test on a corrupted copy or a wrong target. Mutation pass over the reached rows, flipping each conditional and each immediate: each edit runs on every small named case reaching its row and on 40 more, one outcome at a time and cheapest first. 196 of 225 killed, 29 survivors listed in `mutations.tsv`, each with its reason (0 not classified). Those reasons are readings, not proofs of equivalence. Field displacement mutants were not run. 39 unit tests pass.

## Results and limitations

`evidence.json` has the metrics. No progress gate is requested.

- `0x454b700`, `0x4758d70`, `0x454c050` and the hasher are stubs here. The rows show which pointer goes in and the order. Keccak is shown by the rate and delimiter words alone, and the fixture digest is SHA-256.
- Only the `0x4759970` poll copy's round gate is read. `0x439baf0` and `0x4b3c880` are listed as callers, their rows are not compared with it.
- Poll rows before `0x475a3aa` are not in this packet: what happens between stream decode and the join, including any check before the gate.
- What the poll does after an error returns, including the reconnect, is not run. The rows stop at the arm's exits `0x475b407`, `0x475b434`, `0x475a680`, `0x475ac83`.
- The body of the `node_bootstrap` future and `0x4389070` are not run, so what happens to `bootstrapped` after a catch up is not shown.
- The tx join's row growth path `0x454e3f0` is not reached: the row vector is sized up front. Unwind pads and allocation failure exits are not run.
- The channel push `0x4b47b10` is a stub. Who reads the channel is not read.
- A two level tree is the deepest map run.
- No claim about network order, other nodes, or a real chain.

Next question: who builds the commit proof at block `+0x108` on the sending side, and is it the proof row the commit walk `0x44ab970` writes to its outbox?
