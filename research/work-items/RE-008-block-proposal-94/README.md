# RE-008: node #94 block proposal path, from fired timer to signed block on the outbox

This packet shows how a round leader in node #94 builds a block, so the Rust proposer can be written from one ordered list: when it runs, which QC it extends, which pending hashes it takes (oldest first, 100 hashes, 4,000,000 bytes, a 10 s age window), when it may send an empty block, how the block time is chosen, and what it leaves behind when it stops early. No reference file and no PR holds this path: `references/can1357-hl/node/consensus` has no proposer.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference labels are leads only, nothing is copied
- Claim status: observation for every row marked as run or pinned; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: the proposer `0x44b4f80` from entry to outbox push, nine of its leaves run for real, `0x47593a0` among them, the two timers that trigger it, and all seven call sites
- Scope excluded: leader choice inside `0x4b31e70`, the predecessor walk `0x44b9800` (open #613), block digest bytes `0x454c050`, signature bytes `0x14a2710`, what receivers do with the block, the vote path
- Related work: open #49 pins the timeout and TC arms of `0x44adfa0` and the first write of `0x44b6670` and leaves timers as unknown. This packet uses those two functions only as call sites and adds the timer rows. Open #613 owns `0x44b9800`, used here as a stub. #282 lists the proposer's neighbours in a tag census and does not read this path.

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes about 154 s.

```
python3 tools/block_proposal_path.py --out research/work-items/RE-008-block-proposal-94
python3 -m unittest tests.test_block_proposal_path
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`. Function bounds are FDE bounds from the shared parser. Every table below is generated from bytes or from a run of the real rows.

### Observations: when the proposer runs

`triggers.tsv` is a byte scan of every `ff 15` row reading the one slot `0x5773630` that relocates to `0x44b4f80`: 7 sites, no direct call. `pins.tsv` and `jump-tables.tsv` hold the rows below.

- Task start: both copies (`0x2043f70`, `0x22bf220`) call it once after arming the timers.
- `0x44ae334`: the arm that calls `0x44b9a50`, then `0x44ab970` and `0x44aa5a0`.
- `0x44b1816`: the shared tail after `0x44ab970` and `0x44aa5a0`, also reached when `0x44b6670` from a direct TC returns true.
- `0x44b263b`: after `0x44b6670` from a timeout quorum, only on a true return.
- `0x44b26eb`: after `0x44ab560`, only on a true return.
- `0x44ae465`: the second timer, below.
- The second timer: the select leaf `0x20312d0` polls two Sleeps through pointers stored at `0x2045278` and `0x2045280`, which are state `+0x8c0` and `+0x8e0` (the task frame holds the state at `+0xb98`). Result `0xe` becomes event tag `0xc`, result `0xf` becomes tag `0xd`. Tag `0xd` sets `state+0xb00 = 1` and calls the proposer at `0x44ae465`.
- `timers.tsv`: the constructor builds the first timer from f64 `0.3` and the second from bits `0x3fb9999999999999`, one ulp under `0.1`. The real `0x4b27670` turns both into `0 s 300000000 ns` and `0 s 100000000 ns`.
- Round advance `0x44b6670` always rearms the first timer and clears the fired count `+0x9b0`. It rearms the second timer only when the leader of the new round is this node (`0x44b6bcb`), and always clears `+0xb00` (`0x44b6c55`).
- Event time: every event stores its time in `state+0xac8..0xad3` before dispatch (`0x44adfee`, `0x44ae016`), so "now" below is the event time, not a clock read.

### Observations: the ordered path

`gates.tsv` has 24 ordered rows with the site and the case count. In short:

1. Leader lookup for `state+0x918` must succeed and equal `state+0xaec`. Otherwise return.
2. `state+0x928 < round`, else return. `fields.tsv`: that field has one reader and two writers, the constructor and the proposer, so it is a last proposed round.
3. Round above `state+0x988` only logs `Querying stakes for high round, is execution behind?` at `consensus/validator_set.rs:78:13` and goes on.
4. The stake snapshot must exist and hold this node. Otherwise the path touches Once word `0x577ab98` and returns.
5. Parent QC: with no stored TC, the state QC at `+0x438`. With a TC at `+0x8a0`, the QC with the highest round among the TC records from `0x47593a0`, last one on a tie, even when the state QC is higher. An empty TC or a None state QC returns.
6. If word `state+0 == 1`, each pending tx whose tag is neither `0x8000000000000000` nor `...01` and whose `+0x50` byte is 0 is reverified by `0x45485a0` and removed on failure.
7. `0x44b9800` gives either a missing hash or the excluded set. Missing: `0x44b8050(.., 1, 5, 0.0)`, then record tag `0xa` unless that call answers 2, then return.
8. Selection walks the pending map in key order and drops tag `...01`, `+0x50` set, excluded hashes, and txs with `time + 10 s < now`. A tx exactly 10 s old stays.
9. Records sort by time, stable, so equal times stay in key order. Under 21 records `0x4913600` does this. An unsaturated u64 sum of all picked sizes panics on overflow.
10. Take from the front while the running size is below `4000001`, always taking the first tx, up to 100 hashes. The loop stops at the first miss and never skips to a smaller tx.
11. An empty list stops the path unless `0x44b95a0` is true or `state+0xb00` is set. `0x44b95a0` is true when some known block has round above `state+0x198` and a nonzero hash count.
12. `state+0x928 = round` is written here, before the parent lookup. A parent hash missing from `state+0x1b8` then returns with the round marked and the TC kept, so this node sends nothing more for that round.
13. Block time: `event + 0.05 s` if its milliseconds exceed the parent's, else `parent + 0.001 s`. Time addition truncates `seconds * 1e9` to i64 nanoseconds (`0x1459cb6`, `0x1459d11`). `0x14508e0` gives milliseconds clamped at 0.
14. `state+0x8a0` becomes None and the TC moves into the block. `0x454ad50` signs with the key at `state+0x9d0`, and `0x44c2380` pushes a `0x168` byte record with tag 2 to the Vec at `state+0x4d0`.

`layouts.tsv` has the block: hashes `+0`, QC `+0x18` (0x50 bytes), TC `+0x68`, round `+0x88`, time `+0x90`, proposer `+0x9c`, 0xb0 bytes, then 0x41 signature bytes. The block map value stride `0xf8` and the fields `0x44b95a0` and the parent lookup read match that layout.

### How it was run

`functions.tsv` lists ten real functions, 6599 of 7639 bytes reached. The real rows of `0x44b4f80` run from the first byte under an x86-64 row evaluator in the tool, over real B-tree nodes at the node layouts the code reads, one and two levels. `stubs.tsv` names every edge. Each stub checks its arguments. `spec_run` is a separate rule list with no instruction rows, and it predicts the outbox, the logs, every stub call, the f64 passed to time addition, and exactly which state words change. 327 cases, 87 named and 240 vectors, all match; `cases.tsv` holds each one and `outcomes.tsv` the totals. All 11 outcome labels are reached.

### Inferences, kept apart

- Names (proposer, leader, QC, TC, last proposed round, outbox, pending map) are labels. The ELF is stripped. `QC`, `TC`, `proposer`, `round`, `tx_hashes`, `time` agree with field names in the reference comment for `Block`, which is a lead.
- Tag 2 as a block message and tag `0xa` as a block request are read from what these rows put in them, not from a serializer.
- Size at `value+0x48 -> +0x20` as a byte size is inferred from the 4,000,000 cap.
- The second timer constant equals `0.3 / 3` in f64 bit for bit, so it may be a folded `0.3 / 3`. The bits are the only proof.
- First timer = round timer and second timer = leader idle timer are readings of the arms: the first counts fires at `+0x9b0`, the second forces an empty block. A leader with no work therefore sends an empty block about 0.1 s after the round starts, if the timer path holds as read.
- Reverification under word `state+0 == 1` is read from the call shape of `0x45485a0`. What sets that word is not read.

### Differences from the reference

- `node/consensus/timer.rs` documents `0x44ADFA0` path `0x0b` as clearing `state+0xb00`. The arm at `0x44ae44d` sets it to 1, and the clear lives in `0x44b6670`.
- `node/consensus/state.rs` has `DEFAULT_MISSED_ROUND_BACKOFF = 200 ms` and `timer.rs` has `ROUND_TIMEOUT = 60 s`. The two timers armed at round advance are 0.3 s and 0.1 s.
- `node/consensus/state.rs` models `0x44AB560` as `register_client_block`. It is a caller of the proposer here, and its name is not settled by this packet.

## Implementation and comparison

Rust implementation: not yet implemented. `spec_run` in the tool is the comparison model. Original rows against the rule list: 327 of 327 equal, compared on the observations listed above. Controls: `pins.tsv` 55 byte rows, 4 jump table rows, 6 rodata constants, a byte scan for the 7 call sites and for the sites of two state fields, each with a negative test on a corrupted copy. Mutation pass over reached rows of the ten functions, flipping each conditional and each immediate: 252 of 322 killed by 124 small cases, 70 survivors, each with a written reason class in `mutations.tsv`. Those reasons say why these cases cannot separate the edit; they are not equivalence proofs. Field displacement mutants were not run, to keep a run short.

## Results and limitations

`evidence.json` has the metrics. No progress gate is requested.

- `0x4b31e70`, the leader rule itself, is a stub that returns the case's answer. `0x44b9800` is a stub, so the excluded set and missing hash are inputs here.
- `0x1459ca0` is a stub with the rule read from its rows. It works inside one day, so date rollover is not run. `0x42b27e0` is a leaf-only stub, so prune cases stay in one leaf.
- Records from 21 up use a stable sort stub in place of `0x4486310`. Rows below 21 are real. The same key in the large path is assumed.
- The Once word at `0x577ab98` is reached, and what it initialises is not read. Its result is unused on this path.
- The lookup at `0x44b5bc5` of `state+0x58` has no reader of its result. Why it is there is unknown.
- Unreached proposer rows are not listed one by one. They include panic exits and unwind pads.
- All fixtures share one date word, so the signed date compares at `0x44b5b85`, `0x491369d` and `0x491372a` are read, not proved by a case.
- The field census covers FDEs in `0x44a8420..0x44c3000`. A function using another base for the state is not covered.
- No claim about network order or receivers. Whether other nodes reject a block that breaks these limits is not read.

Next question: what does the leader rule in `0x4b31e70` compute, and does a voter check the same 100 hash, 4,000,000 byte and time rules, or only the proposer key?
