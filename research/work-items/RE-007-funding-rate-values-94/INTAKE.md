# Scope, ownership and source record

Research base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; target is the authenticated node94 artifact named in the contract. Repository `docs/SCOPE.md` calls for independently authored buildable Rust and permits static analysis while excluding captured execution without separate authorization. `docs/TASKS.md` places this risk/funding work in RE-007 with explicit helper and unknown-branch obligations. No progress/completion gate is requested.

Prior work is credited directly:

- [#860](https://github.com/lalalune/hyperliquid-source/pull/860): confirmed merged by current metadata; owns the scalar rate/premium formula and explicitly lacks Rust. Its original evaluator was not run. This packet adds a complete conditional exact-bit contract and a planned source implementation, including signed-zero/NaN distinctions that its comparisons did not fully qualify.
- [#899](https://github.com/lalalune/hyperliquid-source/pull/899): rate-map caller and distribution context. Only the selected request boundary is used here; no broad distribution claim is repeated.
- [#1165](https://github.com/lalalune/hyperliquid-source/pull/1165): parameter writers, read as context. Their parser and runtime admission do not prove that every arbitrary raw-bit state in this value API occurs live.
- [#1502](https://github.com/lalalune/hyperliquid-source/pull/1502), [#1422](https://github.com/lalalune/hyperliquid-source/pull/1422) and [#1544](https://github.com/lalalune/hyperliquid-source/pull/1544): separate returned-record storage, impact walk and per-user worker. No source dependency on their open branches is introduced.

Current intake used latest100 open PR bodies (numbers1447..1546), a funding/address search, current #860 metadata, and complete changed paths of #1542/#1543/#1545/#1546. The coordinator's earlier full-path review through1541 is reused as bounded context. New scopes were u256 bounds, float text formatting, fused limb multiplication and level-index formatting; no funding-rate collision was detected. The first #860 metadata call used the wrong connector argument name and failed validation; the corrected call succeeded. Search result null status fields and missing matches are not evidence of exhaustive absence. Older assigned/private work and later PRs are not ruled out; intake must be refreshed before publication.

Scout search accounting: two GitHub search calls, four full-path reads, two metadata calls including that failure, and one web search call with two Intel queries. The scout also used three web read calls, including a failed26MB combined-PDF fetch and successful official standalone source. Exact retained snapshots and query ledger live in the campaign's `wave9_funding_rate_scout.json`; they are research provenance, not runtime inputs.

After that checkpoint, one additional author web search call (two MINSD/MAXSD queries), an official Volume2B open and a find call confirmed the cited edition/entries. The coordinator separately reviewed the official source and native/corpus drafts. That parallel review is not an extra independent observation of the captured runtime. Only these primary ISA sources support floating semantics:

- [Intel Volume1, 253665-080US, June2023](https://cdrdv2-public.intel.com/782149/253665-sdm-vol-1.pdf), arithmetic NaN/indefinite/rounding relation.
- [Intel Volume2B, 253667-084US, June2024](https://cdrdv2-public.intel.com/825757/253667-sdm-vol-2b.pdf), finite MINSD/MAXSD operand selection.

These editions are not described as latest, and ISA assumptions are not measured CPU/MXCSR facts. All project artifacts form one source lineage; separate GNU/LLVM decoding only corroborates bytes and partitions. No unlicensed inferred reference code was copied or imported. Only this new packet is edited in the pre-source phase; there are no source, Git, network-target, signing, transaction or publication actions.
