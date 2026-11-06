# RE-001: node #115 settled-history JSON admission

The successful history writer does not determine what a reader accepts. This
packet recovers the outer input contract for the spot clearinghouse's `soh`
member: whole-member defaulting, required child fields, duplicate precedence,
unknown-key handoff, positional arity and closing-error precedence. Nested value
grammars remain explicit dependencies, so this is not a complete JSON codec or
a claimed native round trip.

- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes.
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: original ELF virtual addresses; exclusive function ends.
- Denominator: 15 complete FDE bodies, 35,630 bytes. Parent and nested helpers
  are retained as context; all component acceptance gates remain false.

## Identity and the defaulting boundary

The parent key classifier `0x22e2ab0` recognizes the exact decoded three-byte
name `soh` and returns variant 13. The parent reader `0x1eeeca0` dispatches that
variant through its table at `0x5d10ac` to `0x1eef2f2`, then calls the child
`0x1e8c2c0` at `0x1eef996`. The successful 280-byte history value is installed
at offset `0x3b8` in the parent's assembled value: its destination at
`rsp+0xfd8` is relative to the `rsp+0xc20` source base of the parent's
`0x5f0`-byte assembled-value copy at `0x1ef0d57`–`0x1ef0d64`. These call/table/layout facts
bind the child to the corresponding writer member; matching field names alone
would not establish identity.

For an otherwise admitted parent object, absent `soh` calls `0x1d79180` at
`0x1ef14b8`. If that constructor returns normally, its three dense collections
and two queues are empty. Their data pointers are the observed non-null empty
sentinels, not allocated elements. The constructor also obtains container hash
state from thread-local machinery; this packet does not reproduce those seeds
or all initialization/failure effects.

This default is at the **whole member** boundary. A present empty child object
does not select that constructor: it fails the first required-field check. The
child is also named by retained metadata as `SettledOutcomeHistory with 5
elements`.

## Present-child contract

After the exact whitespace set `{tab, LF, CR, space}`, the reader admits `{` or
`[`. Field names below are decoded keys from the retained string-parser handoff;
the packet does not independently reconstruct escape decoding.

| Position / missing-field priority | Decoded map key | Child-reader boundary |
| ---: | --- | --- |
| 0 | `sots` | `0x1e3d400` |
| 1 | `sotq` | `0x1e39ae0` |
| 2 | `sqts` | `0x1e2fa90` |
| 3 | `sqp` | `0x1e3c940` |
| 4 | `sqpq` | `0x1e38660` |

The map form accepts these known fields in any order. Every field is required;
there are no per-field defaults in this child. At map end, missing fields are
checked in the table's order. A known duplicate is rejected as soon as its key
is classified, before consuming its colon or invoking that value's reader. It
is neither first-wins nor last-wins behavior.

An unknown key takes the colon path and invokes the value walker at
`0x1d75560`. A zero return resumes map scanning; a nonzero return propagates its
failure. Repeated unknown names do not occupy a known field slot. This is a
walker outcome contract, not a claim that arbitrary malformed unknown values
are accepted or that this packet implements the walker's recursive grammar.

The sequence form calls the same five child readers in the table's order.
Ending before positions 0–4 produces the corresponding invalid-length result.
After the fifth child, the closing helper requires `]`; a sixth element is not
silently ignored. Both forms reject a trailing comma. The retained native
diagnostic tags are 21 for that trailing-comma case and 22 for the observed
extra-value/closing-shape case; exact rendered error prose is outside the model.

Nested child success/failure is an explicit input to the outer relation. This
packet retains the complete child wrapper bodies and their callsites, but does
not infer their full value grammar from the successful writer's output.

## Depth, cleanup and error precedence

Unless the parser's depth-check bypass flag is set, entry decrements its depth
byte. A starting budget of one yields diagnostic tag 24 when it reaches zero.
A zero starting budget reaches an internal invalid-state path and is not treated
as an ordinary supported parser state. For admitted bodies the depth byte is
restored before the closing helper. Bypass leaves the depth byte unchanged.

Map and sequence closing helpers are called even after a body failure. If both
the body and closing helper report errors, the original body error wins; the
later error is cleaned up. If the body succeeds but closing fails, the closing
error is returned and the constructed value is dropped. Thus missing fields,
duplicates or a child failure must not be replaced with a later delimiter
error merely because the finalizer also runs. Exact allocator/drop equivalence
and diagnostic line/column formatting remain outside the claim.

## Validation and reproduction

`verify.py` authenticates the whole target, full unwind extents and body hashes,
GNU/LLVM exports, data/jump tables, direct and relocated calls, source Locations,
incoming relocation sites and 29 instruction obligations. Deep corruption
controls check those layers independently of the outer image digest.

`relations.py` derives keys, missing order, child targets, duplicate branches,
parent dispatch, default lengths, whitespace and framing operands from the
captured instructions. It checks all 120 field orders, every field-presence
subset, duplicate-before-child precedence, unknown-key success/failure,
sequence lengths and child failures, all byte values for whitespace and all
depth-byte states. Four evidence mutations alter the modeled outcome: a known
key's spelling, duplicate-branch polarity, whitespace mask and depth diagnostic.

The relation uses decoded-key events and supplied child/walker outcomes. Its
synthetic cases are not native execution fixtures or a byte-complete JSON
decoder. No captured code is executed or emulated.

```sh
python3 research/work-items/RE-001-node115-settled-history-json-admission/verify.py
python3 research/work-items/RE-001-node115-settled-history-json-admission/relations.py
python3 -m unittest discover -s tests -p test_node115_settled_history_json_admission.py -v
make doctor
make verify test catalogue-check reproduce
```

`validation.json` and retained logs give observed commands, versions and
results. Hosted CI, a full parent schema, source-equivalent TLS state, complete
child grammars, native round trips and whole-component completion are not claimed.

## Prior work

GPT-6.1 Terra screened visible open and closed PRs plus retained historical
exclusions. `pr-census.json.bz2`, `scope-audit.json` and `overlap-summary.md` record
the comparison. Missing API patches and unavailable historical records limit
the no-overlap conclusion.

The companion settled-outcome-history text packet establishes successful
output shape and explicitly leaves readers/defaults open. This input contract
answers a distinct question: accepted container forms and failure/defaulting
behavior cannot be inferred from that output.

[#1674](https://github.com/lalalune/hyperliquid-source/pull/1674) and
[#1875](https://github.com/lalalune/hyperliquid-source/pull/1875) cover different
older spot-metadata and OutcomeTracker readers. [#2149](https://github.com/lalalune/hyperliquid-source/pull/2149)
and [#2227](https://github.com/lalalune/hyperliquid-source/pull/2227) own separate
selected `ctx` height paths. Those contracts are not reintroduced here. The
parent is retained only to bind `soh`, its absent-member constructor and layout.

Independent prose and checks are MIT-licensed under the repository license;
captured artifacts retain their original provenance.

The later overlap refresh is retained in `final-overlap-refresh.md`. Previously observed PRs absent from the refreshed listing remain overlap exclusions; unavailable historical contents, missing API patches and later work limit the conclusion.

The full 584-file suite ran on the history-text branch. Each companion branch independently matched the base input hashes and passed its own focused tests and integrity checks; `validation.json` distinguishes reused suite evidence from branch-specific commands. The original base had a stale generated README inventory count; regenerating the catalogue resolves that pre-existing check failure.
