# RE-017: connect one admitted ABCI digest vote to the replay comparison input

- Component ID: abci / storage
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Analysis base commit: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`. The captured binary's source commit is not recovered; its identity here is the pinned target digest.
- Claim status: selected instruction and pointer-flow observations; same-owner join is conditional; external H+1/root semantics and other producers remain unresolved.
- Scope: join the already-recorded ABCI digest-vote handler and replay reference consumer through the state-relative tracker at `+0x3e50`. This packet does not claim a quorum threshold, a canonical root, an H+1 relation, or all-path provenance.

## Reproduce

From the repository root, with Python 3.12 and the standard library plus the repository's shared ELF reader:

```sh
python3 research/work-items/RE-017-node115-vote-to-replay-root-provenance/verify.py
python3 -m unittest tests.test_vote_to_replay_root_provenance_115
python3 tools/hash_signature_record_115.py --out /tmp/hash-signature-record-115
python3 research/work-items/RE-017-node115-digest-reference-handoff/verify.py
```

The new verifier reads the pinned ELF and checks exact instruction bytes, direct-call targets and function boundaries. The cited predecessor verifiers reproduce the complete admitted-record body and selected tracker-to-replay handoff. The target is not executed.

## Evidence

The accepted path for action tag `0xdd` reaches `0x294FDD0` through the dispatcher recorded in [RE-010](../RE-010-node115-digest-vote-handler-tracker/README.md). The handler's message is separate from its state owner: the message supplies a 32-byte digest at `+0x0`, a height at `+0x20`, signature storage at `+0x28`, and a 20-byte identity in the third argument. Existing RE-010 evidence records the signature/recovered-identity checks and the height bound before the tracker call.

On that accepted branch:

- `0x294FDEF` forms the signature pointer from message `+0x28`; `0x294FDFC` and `0x294FE00` copy the message's 32 digest bytes into the local record at `+0x10`.
- `0x294FEE8` stores the message height at record `+0x8`. The signature pointer is stored at record `+0x0`, and the third-argument identity is copied at record `+0x30`.
- `0x294FEE1` passes owner `+0x3e50` as the tracker to `0x2760BC0` at `0x294FF53`.
- The complete `0x2760BC0` record path is covered by [the hash-signature record packet](../RE-017-hash-signature-record-115/README.md). It looks up and inserts by the record's exact height and 32-byte digest in that tracker. Its special initial-height digest copy at tracker `+0x92` is a separate field and is not treated as the replay comparison source here.

The selected replay finalizer independently passes owner `+0x3e50` to `0x5AFA030` at `0x548BF2D..0x548BF4B`. [The merged digest-reference handoff packet](../RE-017-node115-digest-reference-handoff/README.md) follows the selected callback and exact-height tracker lookup, then shows the resulting row digest reaching the replay comparator. The comparator's other operand is a lookup in local history at context `+0x400`; the ABCI digest-quorum descriptor at `+0x280` is a sink and is not used as the source of the row digest.

This joins two independently evidenced paths by the same owner-relative tracker field and its height/digest map contract. It is conditional on the handler and finalizer referring to the same state instance and on the selected callback path. It does not establish that the vote and replay occur in one observed runtime, that the selected row is exactly height H+1, or that its digest is a canonical or trusted chain root. The message's digest provenance is established for this admitted handler path; the wider set of producers and the root/H+1 policy remain open.

## Results and limitations

- Result: one digest that passes the selected ABCI digest-vote admission path can be traced, with its message height, into the tracker field used by the selected replay-reference path. This supplies a provenance-bounded candidate input for an offline fixture.
- Not established: quorum threshold/weight, equivocation policy, all tracker writers, identity of a particular runtime state instance, mapping from the row height to H+1, external canonical-root authority, or replay success.
- No component gate changes. The qcp expected-root question remains partial; this evidence narrows its missing-provenance statement but does not close the H+1/root relation.

## Prior art and overlap

- [#4114](https://github.com/lalalune/hyperliquid-source/pull/4114) records the selected digest-vote handler and tracker call; reused, not claimed as new.
- [#4157](https://github.com/lalalune/hyperliquid-source/pull/4157) records local-history comparison and leaves external H+1 provenance unresolved; reused, not claimed as new.
- [#4117](https://github.com/lalalune/hyperliquid-source/pull/4117) records digest-quorum descriptor handoff; reused to keep the sink separate from the comparison source.
- [#7057](https://github.com/lalalune/hyperliquid-source/pull/7057) maps a different replay-slot writer/reader pair and explicitly does not establish expected-root provenance.
- [#7048](https://github.com/lalalune/hyperliquid-source/pull/7048) is an open adjacent packet on the false-to-true digest-selection transition and selected consumer fields. This packet does not repeat that transition: it adds the caller-level observation that the admitted handler and selected replay finalizer each pass owner-relative field `+0x3e50` to their respective tracker paths. The same runtime owner instance remains conditional.
- [#7049](https://github.com/lalalune/hyperliquid-source/pull/7049) and [#7053](https://github.com/lalalune/hyperliquid-source/pull/7053) are open adjacent packets on the support predicate and pre-insertion admission. They are not used to claim complete eligibility, vote admission, or quorum policy here.
