# RE-001: node #115 TWAP cancellation empty-error handoff

An internal cancellation error does not by itself establish that earlier
mutations were undone. Prior work located a count store before a possible
`0xd4` removal error, and an empty record vector passed to route-specific
handoffs. This packet closes that **selected continuation** through the two
handoffs, their empty drops, the core return and the immediate wrappers.

The result is conditional: if the compact removal count-store path is reached,
the removed row has tag two, and the observed native storage/ABI premises hold,
the traced continuation does not restore the preceding count store. It processes
no route records. This is not a claim that the combination is externally
reachable, an exploitable defect, or that an outer transaction commits it.

- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes.
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; exclusive function ends.
- Denominator: nine complete FDE bodies, 15,080 bytes. Unselected branches are
  retained as context, not claimed as reconstructed. All component acceptance
  gates remain false.

## The joined path

| Stage | Perpetual route | Spot route | Observation |
| --- | --- | --- | --- |
| Compact count store | `0x2d2c9cb` | `0x2d2d30b` | Store decremented qword at selected descriptor +24 |
| Removed-row tag test | `0x2d2ca4f` | `0x2d2d38f` | Tag two selects the absence sentinel |
| Error result | `0x2d2ccd6` | `0x2d2d616` | Write error `0xd4` and result variant one |
| Core consumes error | `0x2c2f13e` | `0x2c2f215` | Copy the error and skip record construction/append |
| Route handoff | `0x2419810` | `0x241a3c0` | Empty record vector skips the processing body |
| Empty drop | `0x2822f50` | `0x2824790` | No elements and zero capacity: return without calls |

The removal functions are `0x2d2c6e0..0x2d2d019` and
`0x2d2d020..0x2d2d959`. Their compact paths decrement the selected count after
the shifting helper has returned. This packet starts its new continuation claim
at that store. Earlier lookup, movement and removal behavior is credited to
[#2202](https://github.com/lalalune/hyperliquid-source/pull/2202).

The selected descriptor is in the compact representation: its first qword is
not the `0x8000000000000000` tree marker. Consequently the later
`tree-marker && count < 32` conversion condition is false. On the selected
tag-two path, no conversion helper or other call intervenes between the count
store and the `0xd4` return. The retained path ledger lists every explicit memory
destination: only the initial descriptor +24 store is directed at the selected
state descriptor; subsequent writes are to stack scratch and the result.

The cancellation core `0x2c2f020` initializes each route's temporary vector to
`(capacity=0, pointer=8, length=0)` before removal. Result variant one copies the
error payload to the core's result scratch and jumps past record construction.
The perpetual route passes the unchanged empty descriptor to `0x2419810`; the
spot route passes it to `0x241a3c0`. The existing body of an event/record handler
must not be assumed to run merely because its entrypoint is called.

Both handoffs take the vector's descriptor and replace the supplied descriptor
with another empty one. They compute the end pointer from length and stride
(696 bytes for perpetual records, 712 bytes for spot records). With length zero,
the branch goes directly to the corresponding drop. The nonempty dispatcher,
state offsets and record-dependent calls are bypassed.

Each drop receives equal current/end pointers and zero allocation capacity.
The element loop is skipped, the deallocation branch is skipped, and the drop
returns without making any call. There is no state pointer dereference or state
write on these selected handoff/drop paths. Descriptor resets affect the core's
temporary stack vector, not the earlier selected removal descriptor.

The core then copies the saved error and returns. Both immediate wrappers pass
their original state pointer into the core and, after its return, only copy the
result to their output, set outer variant five and return. The wrapper behavior
is credited prior work; here it closes the new handoff proof's endpoint. Outer
variant five is not treated as proof of successful cancellation. Its nested
result remains the internal error.

## Premises and limits

The selected compact store must actually have been reached and earlier helpers
must have returned normally. The removed-row tag is two. The observed stack
outputs, scratch vectors and state descriptors must denote valid storage with
the native call ABI's distinct output locations. The packet does not derive
input fixtures that make this state combination reachable from a public request.

No conclusion is drawn about the tree-conversion route, errors before the count
store, arbitrary pointer aliasing, invalid memory, panics in earlier helpers,
transaction-wide rollback, snapshot replacement, durable writes, block commits
or live-system effects. In particular, **“no restoration in this traced
immediate continuation” does not mean “committed despite an error.”** The source
reconstruction should preserve this distinction until the outer ownership and
transaction layers are independently established.

## Evidence and checks

`verify.py` authenticates the pinned whole image, full FDE extents and body
digests, GNU/LLVM exports, instruction spans, direct/relocated calls, source
Locations and incoming relocation sites. `records.json` retains unresolved
dependencies outside the selected path. `obligations.json` binds 24 relevant
native spans. Deep corruption controls independently reject changed body,
instruction, relocation, source-data and unwind evidence.

`relations.py` retains ten selected path certificates. Their instruction
boundaries and branch edges are checked against the image, their call lists are
closed, and their explicit memory destinations are constrained by stage. The
call closure is two core-to-handoff calls and two handoff-to-drop calls; the
selected removal, drop and wrapper continuations contain no calls. Branch
predicates are tied to the compact/tag-two/empty/zero-capacity premises above.
This is static control/dataflow analysis, not an instruction interpreter.

The abstract boundary relation checks the resulting count, internal error and
record-processing bypass. Its synthetic counts are arithmetic boundary checks,
not evidence of reachable native states. Four counterfactual evidence changes
alter the relation: count-store offset, internal error number, empty-branch
polarity and outer wrapper variant. These complement body integrity checks;
they do not substitute for the stated premises or establish execution parity.

```sh
python3 research/work-items/RE-001-node115-twap-cancel-empty-error-handoff/verify.py
python3 research/work-items/RE-001-node115-twap-cancel-empty-error-handoff/relations.py
python3 -m unittest discover -s tests -p test_node115_twap_cancel_empty_error_handoff.py -v
make doctor
make verify test catalogue-check reproduce
```

Exact commands, versions, results and logs are retained in `validation.json`.
No target code was executed or emulated; hosted CI, native execution parity and
full-component completion are not claimed.

## Overlap assessment

GPT-6.1 Terra compared visible open and closed PRs and retained unavailable
historical exclusions. `pr-census.json.bz2`, `scope-audit.json` and
`overlap-summary.md` record the comparison and its limitations. Missing patches
and unavailable historical records preclude an absolute uniqueness guarantee.

- [#2202](https://github.com/lalalune/hyperliquid-source/pull/2202) owns removal,
  the possible post-store error, empty-vector callsites and immediate wrapper
  copy. It explicitly leaves the route handoff effects unresolved. Those parts
  are credited context; the joined error continuation is the new question.
- [#2138](https://github.com/lalalune/hyperliquid-source/pull/2138) reaches these
  handoffs from scheduled cancellation; [#2241](https://github.com/lalalune/hyperliquid-source/pull/2241)
  references the perpetual handoff as context. Their available patches do not
  establish the empty TWAP-error continuation.
- [#2911](https://github.com/lalalune/hyperliquid-source/pull/2911) owns TWAP
  result serialization; [#1058](https://github.com/lalalune/hyperliquid-source/pull/1058)
  is credited nearby TWAP prior work. This packet adds neither a result codec
  nor a new cancellation admission policy.

Independent prose and static checks are MIT-licensed under the repository
license. Captured artifacts retain their original provenance.

The later overlap refresh is retained in `final-overlap-refresh.md`. Previously observed PRs absent from the refreshed listing remain overlap exclusions; unavailable historical contents, missing API patches and later work limit the conclusion.

The full 584-file suite ran on the history-text branch. Each companion branch independently matched the base input hashes and passed its own focused tests and integrity checks; `validation.json` distinguishes reused suite evidence from branch-specific commands. The original base had a stale generated README inventory count; regenerating the catalogue resolves that pre-existing check failure.
