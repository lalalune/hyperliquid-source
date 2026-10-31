# RE-008: node #94 commit rule and ancestor walk, 0x44ab970 from the first byte to the outbox

This packet shows that `0x44ab970`, labelled `verify_block` in the reference tree, is the block commit path of node #94, so the Rust node can be written from one ordered rule: the top block's QC names a child, the child's QC names the block to commit, the two must be in consecutive rounds, and the whole ancestor walk down to the committed round must succeed before anything changes. It also pins what the commit does next: which txs and blocks leave memory (20 s, committed round), the 100,000 entry seen map, the proof carried with each record, and the one-shot request throttle that fills the gaps.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference labels are leads only, nothing is copied
- Claim status: observation for every row marked as run or pinned; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: `0x44ab970` from entry to return, nine helpers run for real (`0x47c05f0`, `0x489b640`, `0x48980c0`, `0x4942500`, `0x44b8050`, `0x4356a60`, `0x492d4b0`, `0x47f51e0`, `0x1447130`), both call sites, the 100,000 constructor limit
- Scope excluded: QC and signature checks before a block enters the map, vote collection, what the outbox reader does with tag 3 and tag `0xa`, throttle row removal, block digest bytes `0x454c050`
- Related work: open #49 and #282 list the dispatcher `0x44adfa0`; here it is used only for the two call sites and three jumps. Open #613 owns `0x44b9800`, a different walk over the same block map, not used here. Open #664 names `0x44b8050`, `0x44c52b0`, `0x454c050` and `0x447e5c0` as callees of `0x44aa5a0`; of these only `0x44b8050` runs here. `research/work-items/RE-008-consensus-wire-state` has `0x44ab970` as one inventory address with no semantics.

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes about 60 s.

```
python3 tools/commit_walk_path.py --out research/work-items/RE-008-commit-walk-94
python3 -m unittest tests.test_commit_walk_path
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`. Function bounds are FDE bounds from the shared parser. Every table below is generated from bytes or from a run of the real rows.

### Observations: when it runs

`triggers.tsv` comes from a byte scan of every `e8` and `e9` rel32 in `.text`, plus a check that no relative relocation holds the address. There are exactly two sites, both in `0x44adfa0`, and each is followed by `0x44aa5a0` and the proposer slot:

- `0x44ae320`: the arm that calls `0x44b9a50` for one tx.
- `0x44b1802`: the tail reached by three jumps out of the arm that calls `0x44b8410`, so it runs on success and on failure of that call.

So commit is tried after a tx event and after a block event, not when a vote or QC alone arrives. `state+0xac8` holds the event time, written before dispatch at `0x44adfee` and `0x44ae016`, and every age below is measured against it.

### Observations: the rule

`gates.tsv` has 21 ordered rows with sites and case counts. In short:

1. Empty block map: return.
2. Tip: the highest `+0x88` round in the map. A later key wins a tie (`cmovbe` at `0x44abba7`).
3. Child: the block named by the tip's QC hash `+0x48`. Missing: request reason 0.
4. Start: the block named by the child's QC hash. Missing: request reason 0.
5. `child.round == saturating(start.round + 1)`, else return. The tip's own round is not compared to the child's, and the QC round at `+0x40` is not compared to anything.
6. `start.round` at or under `state+0x198` skips the walk. Equal goes to pruning; under returns with no write.
7. The walk starts at `start` and follows each block's QC hash. For each block above the committed round: every hash must be in the tx map with a tag other than `0x8000000000000001`, else request reason 1 for this block. The parent must be stored, else `0x14385c0` runs, then request reason 2 for the parent hash.
8. The walk stops at the first parent at or under the committed round. Equal round: go on. Lower round: return. This compares rounds only. No committed hash is read in this function.
9. Any stop before step 8 passes drops the partial records. Only the request throttle row and a possible request row on the outbox change: all blocks in the walk commit together or none do.
10. `state+0x198 = start.round`. Prune steps 12 and 13 run only past this line, so a blocked walk also keeps old txs and blocks.
11. With at least one record: stats 0, 1, 2 (blocks, txs, bytes, the last two capped at i64 max), the `committed` log with block hashes and tx hashes in walk order, then each tx leaves the tx map, gets a sample 0x12 of event time minus tx time, and its `+0x51` byte goes to the seen map at `state+0x38`. A second removal of the same hash does nothing.
12. Txs with `time + 20 s` strictly below event time leave the map whatever their tag: log `dropping txs`, stat 3. A tx exactly 20 s old stays. The time add is the chrono call at `0x489b707`, immediate `0x14` at `0x489b6f6`.
13. Blocks with round strictly under the committed round leave the map, on any branch: log `dropping blocks`. The block at the committed round stays, which is what ends the next walk.
14. Records are reversed, oldest first. For each one, samples 0x10 (block time gap) and 0x11 (wall gap) go out, `+0xad4` and `+0xae0` update, then `0x47f51e0` pushes one tag 3 row per record to the outbox at `state+0x4d0`.

### Observations: what a commit record holds

`layouts.tsv` has the rows. One record is `0x20` bytes: an Arc of `0x250` bytes (two counts, block `0xb0`, signature `0x48`, proof `0x148`), an Arc of a vector of `0x28` byte tx rows (hash, shared tx record), and the 12 byte block time. The proof is `None` unless `child.round == walked.round + 1`. Otherwise it holds the child block, the child signature, and the grandchild's QC, whose hash is the child. A walked block with a gap above it therefore commits with no proof.

### Observations: the request throttle

`throttle.tsv` lists the rows of `0x44b8050`. The key is tag byte 1, the committed round and the hash. A new key makes a row stamped with event time and sends nothing. A later call sends only when event time is at or after the stamp plus 1.0 s (`0x20a730`, r8 clear at all three sites here) and the sent flag at row `+0x24` is clear, and it sets that flag. Reason bytes 0, 1, 2 collect in a set in the row. A second request for one hash at one committed round needs the row to go away; a move of the committed round makes a new key. A sent request becomes outbox tag `0xa`.

### Observations: seen map

`0x4356a60` keeps a deque at `state+0x38..0x57` and a map at `state+0x58..0x6f`. A key already present gets its byte rewritten and no deque push. While the deque length exceeds the limit at `state+0x70`, the oldest key leaves both. The constructor writes limit 100000 at `0x44a8c82` into a record based at `rsp+0x8e0`, moves that record to `rsp+0x3b8` at `0x44a904a`, and copies `0x238` bytes from `rsp+0x380` to the state at `0x44a97c3`, so the limit lands at `state+0x70`.

### How it was run

`functions.tsv` lists ten real functions, 11607 of 14877 bytes reached. The real rows of `0x44ab970` run from the first byte under an x86-64 row evaluator in the tool, over real B-tree nodes at the node layouts the code reads, one and two levels. `stubs.tsv` names every edge and each stub checks its arguments. `spec_run` is a separate rule list with no instruction rows. It predicts outbox rows, the ordered trace of stats, samples, logs and seen writes, map contents, throttle rows, and exactly which state words change. 359 cases, 59 named and 300 vectors, all match; `cases.tsv` holds each one and `outcomes.tsv` the totals.

### Inferences, kept apart

- Names (tip, child, start, QC, TC, committed round, proof, seen map, throttle, outbox) are labels. The ELF is stripped.
- Reading steps 2 to 5 as a two-chain rule: the child's QC certifies `start`, the tip's QC certifies the child, and consecutive rounds make `start` final. The bytes show only stored blocks and rounds.
- Reading `+0x198` as the last committed round rests on steps 8 and 13 and on the log label `committed`.
- Tag 3 as "committed block" and tag `0xa` as "fetch request" are read from what these rows put in them, not from a reader.
- Reason 0 = chain head parent, 1 = tx, 2 = ancestor are readings of the three call sites. What each byte causes is not read.
- The `0x51` byte's meaning is not known; it is only carried.
- Sample numbers `0x10..0x12` and stat numbers `0..5` have no names here.

### Differences from the reference

- `node/consensus/mempool.rs` and `state.rs` label `0x44AB970` as `verify_block`, checking a candidate against a watermark, duplicates and a sequence index. The bytes take no candidate: the one argument is the state, and the path is the one above. The labels `committed`, `block hashes`, `tx hashes` are a log, not size stats.
- `state.rs::try_commit_from_child_qc` commits from the arriving block with `child_round > parent.round` and reads the QC round. The bytes start at the top block, need two QC links and exact consecutive rounds, and never read the QC round.
- The reference prunes by retention count (`block_retention`) and keeps blocks at or above the commit. The bytes drop every block under the committed round at once.
- The reference has no ancestor walk, no atomic stop, no proof in the commit record, and `locked_round` writes that do not exist in this path.

## Implementation and comparison

Rust implementation: not yet implemented. `spec_run` in the tool is the comparison model. Original rows against the rule list: 359 of 359 equal, compared on the observations listed above. Controls: `pins.tsv` 82 byte rows, 2 rodata constants, 7 strings, one Location and 3 packed line words (`locations.tsv`), a byte scan for the call sites, each with a negative test on a corrupted copy. Mutation pass over reached rows of the ten functions, flipping each conditional and each immediate: each edit runs only on the 40 cheapest of 119 cases that reach its row, to keep a run short. 425 of 555 killed, 130 survivors listed in `mutations.tsv`. Survivors are not classified one by one and none is claimed equivalent; a larger case set may kill some. Field displacement mutants were not run.

## Results and limitations

`evidence.json` has the metrics. No progress gate is requested.

- `0x454c050` is a stub that returns the map key of the block it is given, so the rows here do not prove that a block's map key equals its digest. The code stores that digest as the first block hash and later hashes from QC fields, which is why the stub is shaped this way.
- Block and vector clones are byte copies. `0x44c52b0` and `0x4847500` deep-copy in the real code.
- `0x42b27e0` and `0x42b2030` work at leaves only, so tx removals stay in one leaf. `0x42b43b0` returns the next position with no rebalance. Real B-tree rebalance is not run.
- Chrono calls are stubs read from their use. Date addition moves only the packed ordinal, so a year end is not run. The range panic at `0x489b9de` and the wrap of `0x1447130` overflow paths are not run.
- `0x4958740` is a stub with the rule read from its rows: new row, event time stamp, stat 4, `Registering request`.
- After the first scan finds every tx, the missing branch after `0x47c05f0` (rows from `0x44ac198`) cannot be reached in one thread and was not run, along with panic exits and unwind pads.
- `0x14385c0` is a lazy global getter, its result is unused on this path, and why it is called before reason 2 is unknown. Open #667 covers that getter.
- Where throttle rows are removed (`Pruned rpc request throttle`) and whether the sent flag is ever cleared are not read.
- No claim about QC validity. This path trusts stored blocks; what checks a block before storing it is outside this packet.
- No claim about network order or about other nodes.

Next question: what does `0x44b8410` check before a block enters the map, and does anything read the proof in the tag 3 record?
