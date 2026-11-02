# RE-008: node #94 vote and timeout path, from the vote decision to the QC, and from the timer to the TC

This packet shows how a node #94 validator decides to vote, how the next leader turns votes into a QC, how a QC moves the round, and how the timer and the timeouts of other nodes build a TC, so the Rust node can write these five steps from one rule list. It settles the vote rule (`qc + 1 == round`, or `tc + 1 == round` with `qc` at or over the top QC in the TC, and a TC with no rows refuses even a direct QC), the 50 ms gap and the absolute 3.5 s age limit, that a vote goes only to the leader of round + 1, that stake is counted per block hash in a round, that QC votes are only the ones held when strict 2/3 is passed, the 95 round cut, and the join at just over 1/3 of stake.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference labels are leads only, nothing is copied
- Claim status: observation for every row marked as run or pinned; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: `0x44aa5a0` from entry to return, `0x44add70`, `0x454b020`, `0x454ba50`, `0x435e130`, `0x48c4c10`, `0x48c4120`, `0x44ab560`, `0x4356560`, `0x47bf9c0`, `0x44b6130`, `0x454b170` run for real, and the vote, timeout and timer arms of `0x44adfa0` run from the function's first byte. 49 helpers run for real too, B-tree insert, split and removal among them
- Scope excluded: the leader rule `0x4b31e70`, digest bytes `0x454c050`, signature bytes `0x14a2710` and `0x14c6f50`, the fetch throttle `0x44b8050`, the ancestor walk `0x44b9800`, the body of `0x44b6670` past its entry compare, QC verification `0x4758d70`, what reads the outbox rows
- Related work: merged `research/work-items/RE-008-timeout-round-transition-94` pins the timeout guards, the strict 2/3 compare and the entry of `0x44b6670`, and names `0x44ab560`, `0x44b6130` and `0x47be700` only as unknown or as call targets; this packet runs them and does not repeat its block records. Merged `research/work-items/RE-008-consensus-wire-state` lists `0x454aa10` and `0x4ad90d0`. #282 names error tags of `0x454ba50`; `error-tags.tsv` here says which row raises each tag. #664 names callees of `0x44aa5a0` and states no rule. Our #890, #951, #975 and #999 are the proposal, commit, admission and client block steps next to this one; `0x4ad90d0`, `0x42c9930` and `0x454aa10` run here only as helpers. The reference labels `0x44ab560` as a client block registration; the rows below show a QC record, and the only string in it is `: Bad QCs: `.

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes about 225 s.

```
python3 tools/vote_timeout_path.py --out research/work-items/RE-008-vote-timeout-path-94
python3 -m unittest tests.test_vote_timeout_path
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`. Function bounds are FDE bounds from the shared parser. Every table is generated from bytes or from a run of the real rows.

`gates.tsv` has 79 ordered rows, each with its site and case count. `layouts.tsv` has the vote, timeout, outbox row, tracker and state fields. `triggers.tsv` comes from a byte scan of every `e8` rel32 in `.text` plus a check that no relative relocation holds the address.

### Observations: when a node votes

`0x44aa5a0` has three call sites in `0x44adfa0`: after a tx event, after a block event (both after the commit walk), and event tag `0xe`. It takes no block argument. In order:

1. Round is `state+0x918`. No stake set, or this node (`state+0xaec`) not in it: return.
2. Event time (`state+0xac8`) under last vote time (`state+0xab0`) + 50 ms: return. Equal passes. The time is three words, date, seconds, nanoseconds, added through the real `0x15206e0` and `0x151f870`.
3. The tip is the highest round in the block map, the later key on a tie. Tip round must be over `state+0x920` and over the committed round.
4. Walk from the tip down: each block's tx hashes need a row with a tag other than `...01`. A miss goes to `0x44b8050` kind 3 with the block digest, not the tx hash. A missing parent goes there as kind 4 with the QC hash. An answer other than held becomes an outbox row with tag `0xa`, and the vote stops. Block time must be strictly after parent time. The walk stops at the first parent at or under the committed round.
5. `0x44b9800` over the tip QC. Then each tip tx must be present, not flagged at row `+0x50`, and absent from the ancestor set. A seen map lookup follows through `0x4355db0` and its answer is not read, the same dead lookup the admission packet found.
6. Tip round must equal the current round, and `state+0xb01` must be clear. Once a node has sent a timeout it does not vote in that round.
7. `0x1450a60` gives the absolute difference of event time and block time in whole microseconds, as seconds. Over 3.5 fails. A block 3.5 s in the future passes and one further ahead fails. 3.500000999 s passes, 3.500001 s fails.
8. `0x44add70` is the rule below. Then the leader of round + 1 (saturating). `state+0x920` and `state+0xab0` are written only after that lookup succeeds, so a leader error leaves the node free to vote again.
9. Outbox row tag 4: the vote at `+8`, the leader address at `+0xa0`.

### Observations: the vote rule

`0x44add70`:

- `direct` is `qc round + 1 == block round`, saturating.
- No TC: `direct` decides.
- A TC with no rows: no vote, even when `direct` is true (`0x44addc1`).
- Otherwise `direct`, or `tc round + 1 == block round` and `qc round >= top`, where `top` is the highest QC round over every TC row.
- Block round over `state+0x920`.

The vote is 0x98 bytes: block digest variant 0, version pair copied from the block's QC, round, this node, and a signature through `0x454b020`. This packet stubs digest construction, so its earlier claim that variant 1 signs only the first `0x38` bytes and excludes the signer was not established. The later [full variant-1 writer proof](../RE-008-qc-vote-preimage-94/PROOF.md) includes the 20 signer bytes at payload `+0x38` before the version pair, round and block hash. The old `gates.tsv`/tool fixture wording is retained as historical model metadata, not a native digest oracle.

### Observations: receiving a vote

Event tag 7, arm `0x44afbce`. The arm does not check that this node is the next leader:

1. Round under `state+0x918`: dropped before the signature.
2. `0x454ba50`: stake set (tag `0x28`), version pair against table `+0x40,+0x48` (tag 0 with both pairs), signer in the set, recovery, recovered address (all tag 1). An unknown signer has no recovery run.
3. The seen map `state+0xa68` keeps the highest round per signer. This write comes before the next gate.
4. Round under `state+0x920`: dropped. A vote for the round this node voted in passes.
5. Cut is `round - 95` when round is at least 95.

The tracker at `state+0x238` is a floor plus a map round to row, each row a map block hash to voters. Stake never adds across hashes. `0x48c4c10`: a round under the floor stores nothing. A decided row only gets the voter added, with no quorum read, and that vote is never used. An undecided row reads quorum, inserts (a repeated signer replaces its signature), and reads quorum again. Only false then true decides. Quorum is `0x4ad90d0` over the sorted signer set. A slot that already held quorum when undecided never decides, and fixtures show that row stays open. After a decision, with round at least 95, rows under the cut go and the floor becomes the higher of cut and old floor. Nothing else removes rows: past 100 rounds `0x488b370` lists 100 keys and the list is freed unread (`0x48c5b8c`).

The QC is the voter map at the moment of the decision, as rows of 0x60 in signer order, with the version pair of the last vote, the round and the hash.

### Observations: QC record

`0x44ab560` runs for every QC: built here, in a block, in a TC event, in a timeout. It is the only writer of the highest QC.

- Stored QC at this round: version pair and hash are compared, rows are not. A difference logs `: Bad QCs: ` (`node/src/consensus/state.rs` line 973) and goes on. The first QC stays.
- New round: `0x4356560` inserts and pushes the round to a ring. While the ring count is over the limit at `+0x38` the oldest inserted round is removed, which can be the higher round.
- Round over `state+0x460`: the QC replaces the highest QC at `state+0x438`. Equal does not.
- `0x44b6670` always runs with the QC round, and its bool is the return value. The vote arm runs the proposer on true.

### Observations: timer and timeouts

Event tag `0xc`, arm `0x44ae35a`: fire count `state+0x9b0` + 1, saturating. With `state+0xb01` clear a timeout is sent. With count at least 2 one is sent again, so a count of 2 with a clear byte sends two in one fire. The timer is set to now + `state+0x8c0,+0x8c8`.

`0x44b6130`: timeout = clone of the highest QC, current round, this node, signed over digest variant 2. `state+0xb01` is set. Outbox row tag 5. If `state+0x8a0` holds a TC, a clone goes out as row tag 6.

Event tag 8, arm `0x44afe83`, past the guards already pinned in the merged packet:

- The QC in the timeout goes through `0x4758d70`. A failure does not stop the arm there: the same QC is read again in `0x454aa10`, so the tag comes out twice. A QC that passes goes through the QC record. If that moved the round, the timeout is dropped with no proposer call, since its round is now old.
- After the row is stored: `state+0xb01` clear and `3 * signed > total`, this node joins by `0x44b6130`. The product saturates at `2^64 - 1` (`0x44b252f`, `0x44b28a7`), unlike the 128 bit compare next to it.
- `3 * signed > 2 * total` on 128 bits: rows leave `state+0x9b8` through `0x47be700` in signer order, and the TC goes to `0x44b6670` at the current round.

### Inferences

These are read from rows and strings, not proven by them: the tag 4 row is a unicast to the leader and tag 5 and 6 are broadcasts, the seen map feeds liveness or peer tracking, and the second hash slot map is a leftover of a shared generic since it is never filled here and its iterator ends in `ud2`. The 95 round window as a memory bound is a reading of the arithmetic.

## Implementation and comparison

not yet implemented. The tool holds a separate rule list in Python, used only as the comparison below. No Rust is added.

## Results and limitations

796 cases (196 named, 600 vectors) run the real rows and match the rule list on the ordered trace of calls, logs and error tags, the current, voted, highest and floor words, the tracker walked as trees, the seen map, the QC map, the highest QC, every outbox row and the last vote time. 11346 of 14750 bytes of the 12 subject functions were reached, plus 3514 bytes of the three arms. 429 of 581 condition and immediate mutants are killed, each on up to 12 cases reaching its row, spread over outcomes, plus 16 named boundary cases. Of 152 survivors 15 are named in `mutations.tsv` (unused seen lookup, 100 key list, drop of a replaced result, log rows), and the others are not classified. 71 byte pins, 10 slots, 6 strings and 2 Locations, with negative tests. 52 unit tests pass.

Limits:

- Digest bytes and signature bytes are stubs. The fixture digest covers the fields named above, so this shows what the code passes in, not the encoding.
- `0x44b6670` is a stub of its entry compare. Its clearing of `state+0x9b0`, `state+0xb01` and the timeouts is not modelled, so multi-step cases stay inside one round for timeouts.
- `0x44b8050`, `0x44b9800`, `0x4b31e70` and `0x4758d70` are fixture answers. The first and last are covered by #951 and #975.
- Rows `0x44ab09e..0x44ab0b1`, the check on word 0 of the clone, were not reached. That word is a capacity, so the two tags look unreachable, and this is not proven.
- The arm at `0x44af6a4` (event tags 0 and 1, digest variant 3, tracker at `state+0x278`), the ack path at `0x474fa50` and the second tracker `0x435de00` use the same shape and are not run here.
- Field displacement mutants were not run. Stake sum overflow in `0x4b33770` and `0x4b33990` is not reached. No execution of the binary, no live traffic.

Next question: what reads the outbox rows, and is the tag 4 row sent to one peer, and what do the tag 0 and 1 events at `0x44af6a4` carry that needs a 1000 round window at `state+0x278`.
