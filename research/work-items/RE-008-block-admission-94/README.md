# RE-008: node #94 block admission 0x44b8410, verify_block to the block map, with quorum, QC and TC rules

This packet shows every check a node #94 block passes before it enters the block map, in order, so the Rust node can write `verify_block` and `register_block` from one rule list: proposer, QC, QC round, TC, signature, committed round, duplicate hash, same round. It settles the quorum arithmetic (strict 2/3 of stake over a sorted unique signer set, on 128 bit values), the stake set used for a round (the last table key at or under `round - 200`), the empty QC at the start round, the panic on a QC from a newer hardfork, and that only the highest QC in a TC is verified.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference labels are leads only, nothing is copied
- Claim status: observation for every row marked as run or pinned; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: `0x44b8410` from entry to return, `0x454b700`, `0x47b01b0`, `0x4758d70`, `0x47594f0`, `0x454aa10`, `0x4ad90d0`, `0x42c9930`, `0x42ba100`, `0x47bfcf0`, `0x44b9800`, `0x44518a0`, `0x4451690`, `0x428d080`, `0x42730a0` run for real, both call sites of the body
- Scope excluded: the proposer rule `0x4b31e70`, digest bytes `0x454c050`, signature recovery `0x14c6f50`, the channel reader, what the arm does with a returned error beyond the sites named, votes for a block being built here (`0x44ab560` and the vote path)
- Related work: merged `research/work-items/RE-008-consensus-wire-state` lists `0x44b8410`, `0x47b01b0`, `0x4758d70`, `0x47594f0`, `0x454aa10` and the call edges, and pins the compare in `0x4ad90d0`; it states no semantics for them, and this packet does not repeat that inventory. Open #282 names error tags from formatter tables; `error-tags.tsv` here says which row raises each tag and under what condition. Open #613 owns `0x44b9800`, used here only to show that its result has no effect on admission. #251 binds the first three guards of `0x47594f0` (stake set, empty batch, vote round) and stops there; its tags agree with the rows here, and this packet adds what follows them. #49 lists `0x47594f0` and `0x454aa10` from the timeout arm, a different caller, and leaves their effects open. RE-008-commit-walk and RE-008-block-proposal are the steps after and before this one.

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes about 230 s.

```
python3 tools/block_admission_path.py --out research/work-items/RE-008-block-admission-94
python3 -m unittest tests.test_block_admission_path
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`. Function bounds are FDE bounds from the shared parser. Every table is generated from bytes or from a run of the real rows.

### Observations: when it runs

`triggers.tsv` comes from a byte scan of every `e8` and `e9` rel32 in `.text`. `0x44b8410` has exactly two call sites, both in `0x44adfa0`, and no relocation holds it.

- `0x44b0421`, the block event arm. The block hash is digest variant 0 of the block (`0x44af43e`). The arm runs `0x4758d70` on the block's QC (`0x44af46d`) and calls `0x44ab560` only if that passes (`0x44af484`, `0x44af4f3`). It then calls admission whatever the QC returned, so a bad QC stops at step 3 below and not earlier. The body uses the hash it is given and does not recompute it.
- `0x44b0f6c`, a loop over a list of `0x130` byte rows. An error is logged and the loop goes on.

Both pass the stake table at `state+0x930` (`0x44af458`, `0x44b0e6b`).

### Observations: the rule

`gates.tsv` has 22 ordered rows, `qc-tc-gates.tsv` 29 more, each with its site and case count. In order:

1. Stake set for the block round. None gives tag `0x28`. A round above table `+0x58` only logs `Querying stakes for high round, is execution behind?`.
2. Proposer rule for the round. Its error goes back unchanged. Block `+0x9c` must equal its answer in all 20 bytes, else a warning and tag `0x0c`.
3. QC at block `+0x18` must verify (below).
4. QC round strictly under block round, else tag 4. There is no lower bound: a QC far under the block passes with no TC.
5. No TC: done. With a TC its round must equal block round minus 1 (tag 5) and it must verify.
6. Proposer in the stake set, and recovery of the signature at `+0xb0` over digest variant 0 must give the proposer. All three failures are tag 1. The signature is read last.
7. `0x44b8410`: block round at or over `state+0x198`, else tag 3 with both rounds. Equal passes.
8. Hash not in the block map, else tag 6.
9. Every stored block is read in key order. The first with this round gives tag `0x0e` with both blocks as text. A second block of a stored round cannot enter.
10. `0x44b9800` walks stored ancestors from the QC hash and collects their tx hashes. A loop at `0x44b920e..0x44b9416` then looks each hash of the block up in the seen map (`state+0x58`) and in that set. Neither result reaches a branch that changes anything: found and not found both go to the next hash, and success is written at `0x44b9420`. A block that repeats a committed or ancestor tx enters the map. 39 mutants in this loop and in the walk survive for that reason.
11. Log `verify_block ok`. Up to here a failure logs `verify_block err` and leaves the state alone, tested by the exact set of changed state words.
12. The request row with tag byte 0 and this hash leaves the map at `state+0x1d0`. This is a removal the commit packet left open, for the block variant of the key. A failed block keeps its row.
13. Hashes absent from the tx map are collected in block order and logged as `register_block unknown tx hashes`. Each gets a tx row with event time and tag `0x8000000000000001`, the value the commit walk treats as missing. A repeated hash rewrites its row.
14. If `state+0x230` is clear the block is cloned, boxed and pushed to the channel at `state+0x158` with hash and row word `0x8000000000000000`. On a closed channel (word `+0x1c0` bit 0) the row is dropped and the block still registers. A waker at `+0x100` fires once.
15. The block enters the map. The body makes no request for anything missing.

### Observations: a QC

`0x4758d70`, in order, with an answer held until the version check at the end:

- Stake set for the QC round; none holds tag `0x28` and skips the signatures.
- Each vote row (`0x60` bytes): digest variant 1 over QC hash, version pair and round, 0x38 bytes. Signer in the set, recovery succeeds, recovered address equals signer, else tag 2 at once.
- Signers go through `0x44518a0`: sorted, then `0x428d080` removes repeats. Quorum `0x4ad90d0` over that set; short gives tag 9.
- Version pair `+0x18,+0x20` against table `+0x40,+0x48`. Different pair: if the first word is higher and quorum passed, panic with `observed qc for newer hardfork, crashing.`; otherwise tag 0 with both pairs, whatever the held answer was. So a same version pair word with a different start round is tag 0 even with a full quorum.
- Same pair: round under start round gives tag 7. Round equal to start round is the empty QC: all 32 hash bytes zero and no votes, else tag 8, and the stake check is not consulted. Round above it: the held answer.

### Observations: a TC

`0x47594f0`: stake set for the TC round (tag `0x28`), at least one vote (tag `0x0b`), every vote round equal to the TC round (tag `0x0f`, first mismatch). The vote with the highest QC round is chosen, the later one on a tie, and only that vote's QC is verified, through `0x454aa10` with flag 1. Then every vote goes through `0x454aa10` with flag 0 from a parallel loop (`0x4768f80`, leaf site `0x476f448`, `ecx` cleared at `0x476f446`), so every signature is read and every other QC is not. Voters go to a sorted unique set (`0x4451690`), and quorum short gives tag `0x0a`. Vote layout `0xb8`: QC `+0`, round `+0x50`, signer `+0x58`, signature `+0x70`, digest variant 2.

### Observations: quorum

`0x4ad90d0` walks the address set and looks each one up in the stake tree; a missing address adds nothing. It then adds every stake in the tree. Either add panics on carry (`0x4ad93cf`, `0x4ad9457`). The answer is `3 * signed > 2 * total` on 128 bits: `mul` at `0x4ad961a`, the doubled total with its carry in `rsi`, `cmp` and `sbb`, `setb`. Exactly two thirds fails. Stake, not count. A repeated signer counts once, and every `0x60` row still has its signature read.

### Observations: which stake set

`0x42c9930` with table base `+0`: limit = base + 2000, saturating. Under the limit the bound is the base. At or over it the bound is `max(base, round - 200)`. The answer is the last key at or under the bound (`0x42ba100`). A round in the first 2000 after the base uses the base key whatever later keys exist, and a key at round K applies from round K + 200.

### Observations: layouts and tags

`layouts.tsv` has signed block, QC, TC, timeout vote, stake table, stake tree node, set node and state rows, each with a reading site. `error-tags.tsv` lists 16 tags as the low byte of `0x8000000000000000 + n`, with the raising row and the case count. Strings and four Location records are in `strings.tsv` and `locations.tsv`. The names `verify_block`, `register_block`, `block_hash_to_block`, `estimated_stakes_valid_until` come from these strings.

### How it was run

`functions.tsv` lists 15 real functions, 13559 of 17099 bytes reached. The rows run from the first byte of `0x44b8410` under an x86-64 row evaluator in the tool, over real B-tree nodes at the node layouts the code reads, one and two levels. `stubs.tsv` names every edge. `spec_run` is a separate rule list with no instruction rows. It predicts the return value and payload, the ordered trace of logs, sends and removals, map contents, tx rows, and exactly which state words change. 456 cases, 156 named and 300 vectors, all match; `cases.tsv` holds each one and `outcomes.tsv` the totals.

### Inferences, kept apart

- Reading the pair at table `+0x40,+0x48` as hardfork version and start round rests on the panic text and on the empty QC rule.
- Reading the empty QC as the first QC after a hardfork is inferred from that rule alone.
- Reading the 200 round lag as a delay before a new stake set takes effect is inferred; the bytes show only the bound.
- Reading tag byte 0 in the request key as the block variant is inferred from this call and the tag 1 rows of the commit packet.
- The channel row word `0x8000000000000000` is taken as a block handoff because a block is what it carries. Its reader is not read.
- Calling the loop at step 10 dead code left by a removed check is a guess; the bytes show only that its result is unused.

### Differences from the reference

- `node/consensus/mempool.rs::register_block` uses a `block_sequence_to_hash` map and allows an equal hash at a sequence. The bytes scan the block map for a round and have no such map on this path.
- It pushes a request for missing txs and marks tx rows `committed_by`. The bytes write placeholder tx rows and push no request, and existing tx rows are not touched.
- `state.rs::validate_block_qc` checks QC round first, then a set by the QC round, with an indexed signer list and threshold. The bytes verify the QC first, carry 20 byte signers in rows, dedupe by address, and compare with a strict 128 bit product. `validator_set.rs` says overflow must fail a quorum and not abort; the bytes panic on carry.
- `validate_timeout_certificate` has no highest QC step and no signature step. No reference function has the version pair rules, the empty QC or the 200 round lag in this form.

## Implementation and comparison

Rust implementation: not yet implemented. `spec_run` in the tool is the comparison model. Original rows against the rule list: 456 of 456 equal, compared on the observations listed above. Controls: `pins.tsv` 99 byte rows, 5 relocation slots, 10 strings, 4 Locations, a byte scan for the call sites, each with a negative test on a corrupted copy or a wrong target. Mutation pass over reached rows of the 15 functions, flipping each conditional and each immediate: each edit runs on at most 40 of the 456 cases that reach its row, one outcome at a time and cheapest first, to keep a run short. 497 of 680 killed, 183 survivors listed in `mutations.tsv`, 39 of them in the walk and lookup loop of step 10. The others are not classified one by one and none is claimed equivalent; a larger case set may kill some. Field displacement mutants were not run.

## Results and limitations

`evidence.json` has the metrics. No progress gate is requested.

- `0x454c050` is a stub: a SHA-256 of fixture fields for each variant. The rows show which pointer and variant go in, not the digest bytes. Whether variant 0 covers the block's hash list or time is not shown here.
- `0x14c6f50` is a stub. The recovery curve and message form are not in this packet.
- `0x4b31e70` is a stub, so the proposer schedule is not run.
- The parallel loop `0x4768f80` is a stub that runs real `0x454aa10` in index order and returns the first error. With several bad votes the real loop may return another one. Only the leaf site is read.
- The tx map and block map inserts `0x4958c40`, `0x4959ac0` write into one leaf; a split is not run. The request row removal is a stub, its key is checked.
- `0x4ad9638` and its neighbours (an empty stake tree with a non-empty address set) cannot be reached here: an empty tree fails the signer check first. `0x4ad90d0` has 938 bytes unreached, mostly copies of the tree walk for deeper heights.
- The sort at `0x4913410` is a stub, and sets of 21 or more QC rows or 21 or more TC rows take `0x4488fc0`, which is not run.
- `0x4706810`, `0x47085b0`, `0x4707580` are stubs that read the label fields only. Panic exits and unwind pads are not run.
- Tag 3 reaches a tail at `0x44b04b1` that calls the lazy getter `0x14385c0` when `round + 10` is over the committed round and `state+0xb04` is 2; it is read, not run. What the arm does on success at `0x44b043a` (the map at `state+0xa68`) is not read.
- `0x4547690` also calls `0x454b700` and `0x4758d70`, at `0x4547773`, `0x4547b87`, `0x4547bac`. It is not read.
- No claim about network order, other nodes, or a real chain.

Next question: what does `0x4547690` verify with `0x454b700` and `0x4758d70`, and is it the reader of the proof carried in the tag 3 commit record?
