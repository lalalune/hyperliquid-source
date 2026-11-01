# Scope, existing evidence and concurrent work

The baseline [`node94-consensus-admission` README](../../../src/node94-consensus-admission/README.md) explicitly leaves block/QC/timeout digest construction at454c050 open. The baseline [block proposal packet](../RE-008-block-proposal-94/README.md) supplies the block layout and signer handoff; the [block admission packet](../RE-008-block-admission-94/README.md) states that its SHA-256 fixture digest is a stub and does not establish whether the block hash list or time is included. Those fixtures were not executed or treated as preimage oracles here. This contribution fills selector0's bounded value contract rather than revising their admission model.

Related public work is credited without an exclusivity claim:

| Work | Relationship and boundary |
| --- | --- |
| [PR1391](https://github.com/lalalune/hyperliquid-source/pull/1391) | Selector1 QC vote preimage, signer inclusion and common digest wrapper. This packet independently retains the common native scope and does not read its unmerged source. |
| [PR1467](https://github.com/lalalune/hyperliquid-source/pull/1467) | Selectors2–4 timeout/heartbeat/ack preimages, nested signature projection, common wrapper. Selector0 was explicitly deferred. Reviewed author-written exporter scaffolding was copied into this packet; its runtime dependencies are only pinned baseline files. No public API or expected values from the pending PR are dependencies. |
| [PR1444](https://github.com/lalalune/hyperliquid-source/pull/1444) | Concurrent static selector2 timeout projection. The read-only cross-check agreed on signer+58, round+50, QC fields+18/+20/+28, hash+30 and 96-byte QC rows. This shared projection is credited; the new optional TC composition adds each outer timeout signature before that body and closes selector0. |
| [PR1473](https://github.com/lalalune/hyperliquid-source/pull/1473) | Packed-date addition151f870..151fa9c on validated representations. Read proof and all 26 changed paths at head `daa8e583da9ca5dc98562edbf3f87db08899a6d6`. Our paired time serializer/sizer45c4a40/45c4b50 and raw-word domain are distinct. Its calendar context was cross-checked; its tools/source/fixtures were not executed or copied. |

The pre-code live PR search used `"4776d40" OR "4776ab0" OR "block preimage" OR "selector0" OR "selector-0"`, with all states and recent updates. Returned body matches did not reveal another complete selector0 preimage implementation; that is a bounded search result, not proof that none exists. Root also inspected recent PR bodies/changed paths through1466 before this pre-code phase. Live scope can change and must be checked again before submission.

The baseline RE-005 action-signable packet and its MIT pure Keccak implementation supply the credited hash primitive. This packet retains the native permutation and constants but does not claim a new formal native permutation equivalence. The finite independently derived corpus is not a second observation of the captured program.
