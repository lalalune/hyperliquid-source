# Info conditional queries: real snapshot guard lifetimes

This packet advances issue #3921 by following the existing conditional-query pollers through their nested dispatch descriptors to the actual snapshot reads. Each query function acquires and releases its own reader-count guard around its snapshot pointer load. This closes a query-to-snapshot connection left opaque by the previous caller packet; request decoding, response serialization and payload interpretation remain open. No acceptance gate changes.

## Prior evidence and added scope

`RE-001-node115-info-conditional-second-query` already maps caller `0x29698d0..0x2969e48`: first poll slot `0x6443348` resolves to `0x2982f50`, second slot `0x64431c8` resolves to `0x297e840`, and valid first result tag 1 alone initiates the second query. Its pending/short-circuit/result combination findings are prerequisites here. They are not new claims in this packet.

The new dispatch and snapshot connection is:

| Stage | First query | Second query |
|---|---|---|
| Existing outer poller | `0x2982f50` | `0x297e840` |
| Nested descriptor | `0x64429c0` | `0x64428c0` |
| Descriptor `+0x18` target | `0x297a670` | `0x2979e70` |
| Bookkeeping wrapper | `0x29bdc90` | `0x29c7e40` |
| Concrete query body | `0x2a52620` | `0x2a3ceb0` |
| Guard relative to query state S | `S+0x6a8` | `S+0x6a8` |
| Snapshot pointer field | `S+0xb00` | `S+0xb00` |

The selected path starts with valid native objects, inner state 0, and the bookkeeping wrapper's flag at its argument `+0x20` equal to zero. The enabled bookkeeping path is outside this packet's claim. Ordinary returns from allocation/copy, slow guard, wake, query and instrumentation helpers are premises.

## Pointer provenance

Both outer pollers allocate 48-byte inner futures, copy the context fields including the pair at `+0x10`, initialize byte `+0x28` to zero, install the nested descriptor, and call its `+0x18` slot. ELF relative relocations bind those slots to the two inner routines above.

In each inner routine, let `P = *(*(inner+0x10))`, using qword loads at `0x297a68c/0x297a697` or `0x2979e8c/0x2979e97`. It builds a closure with query state `S=P+0x10`, a query key and flag, plus a separate local context. It passes `P+0x140` to the bookkeeping wrapper. On the selected zero-flag branch, that wrapper forwards the closure to its concrete query body. Consequently the actual reader-count word and snapshot pointer are `P+0x6b8` and `P+0xb10`; the table uses the query body's own S-relative offsets to avoid mixing these bases.

The inner routines copy 216 bytes or 80 bytes of returned query data to their outputs and then set inner state 1. That state write alone does not prove that every possible result excludes the outer poller's pending discriminant; no always-ready claim is made.

## Guard acquisition, snapshot reads, and release

Both bodies load the guard at `S+0x6a8`, test bit 3 and the unsigned `-16` boundary, and attempt an atomic `lock cmpxchg` of `old+16`. A disallowed state or failed comparison takes the same slow helper through slot `0x64e0fd8` (target `0x5bb1a60`). This report assumes the helper's successful normal return supplies the required guard; it does not reconstruct the helper's wait/fairness behavior.

The first body's acquired paths join at `0x2a526b8`. Its two timing arms load `S+0xb00` at `0x2a5274d` or `0x2a52a81`, and pass that pointer with the query key and flag to `0x297bcb0`. They release through `lock xadd -16` at `0x2a5279f` or `0x2a52bda`. The result copy and sole normal return at `0x2a52994` follow the release.

The second body's acquired paths join at `0x2a3cf4f`. Its snapshot pointer loads are `0x2a3cfed` and `0x2a3d142`. The body reads fields from that pointer, including `+0x240` on the recorded first arm, and performs query-specific helper calls. It releases through `lock xadd -16` at `0x2a3d60e` before its final output copy and sole normal return at `0x2a3d894`. The snapshot fields and helper outputs are not assigned public API names here.

Both release paths use the same mask/compare (`old & -14 == 18`) to decide whether to call wake helper `0x5bb2110`. The slot identity, operation, offsets and immediates are checked; the wake helper's contract remains a dependency.

Combined with the prior conditional-caller ordering, the first query's **local** guard is released before a subsequently initiated second query acquires its own. Even when both queries' S values identify the same state owner, this is not one uninterrupted local guard. This evidence does not establish whether a higher-level guard, immutable snapshot, or other synchronization supplies cross-query consistency, and does not demonstrate any actual race or inconsistent response.

## Reproduction and validation

Pinned input: original node/115 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. All addresses are ELF virtual addresses.

```sh
python research/work-items/RE-001-node115-info-snapshot-guards/verify.py
make doctor verify catalogue-check reproduce
```

Use the project's audited offline Python environment with Capstone 5.0.7. `records.json` retains ten windows (5,767 bytes / 1,144 instructions), enclosing FDEs, byte hashes, 92 facts and 21 byte/relocation mutation controls. `verification.json` saves the result. The validator authenticates the original target, decodes from FDE boundaries, and rejects each synthetic mutation with digest checks deliberately bypassed for the mutation. It never modifies or executes the target.

The verifier also constructs ordinary intraprocedural control-flow graphs for the two full query FDEs. Direct conditional branches have both successors; external calls fall through; returns and traps terminate. It checks that:

- The acquired-path join dominates both snapshot loads.
- Every ordinary path to the recorded normal return crosses a release, including every snapshot-to-return path.
- No ordinary path after a release reads the snapshot pointer again within that query.
- The checks are non-vacuous: the snapshot loads and normal return are reachable, and ordinary control flow cannot fall out of the decoded FDE.

There are 301 and 474 reachable instructions in those graphs. Six independent graph controls add edges for a snapshot before acquisition, a return before release, or a snapshot after release, in each body; all are rejected. This graph analysis is not instruction execution or emulation. It does not model exception edges, helper side effects, allocation failure, concurrent memory changes, or branch-condition feasibility. In particular, no unwind/cancellation cleanup claim follows from it.

The full `make test` target is excluded because its discovery includes captured-instruction emulation. Static packet verification and offline repository checks are used instead.

## Overlap and remaining work

The current-main `RE-001-node115-info-future-resume-state` packet covers a
separate future at `0x2979780` and its completion/panic states. It does not
trace either query body or the snapshot-guard lifetimes described here.

Current main and open PR titles/bodies were screened for the nested pollers, concrete query bodies, snapshot fields and guard-lifetime scope. Targeted all-state historical searches also checked those functions; no competing contribution was found. The prior conditional-caller packet is explicitly reused. Historical title/body searches do not prove every historical patch was manually inspected.

Issue #3921 remains open. This packet does not reconstruct the request decoder, public response schema, query payload meanings, snapshot ownership/immutability, complete lock implementation, enabled bookkeeping, always-ready behavior, cancellation, all error paths or runtime equivalence.
