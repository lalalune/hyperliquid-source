# RE-014: five named action structures have different field metadata in #115

- Component: action-wire serialization / release drift; bounded RE-001 range evidence.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes.
- Question: do the one-element struct diagnostics still describe these five action types in #115?
- Observed answer: all five say two elements in #115. Their actual #115 code also passes a two-entry expected-field list with the names below.
- Scope is metadata and argument binding, not a recovered action codec or live transaction.

## The observed difference

| Named diagnostic type | #94 element-count text | #115 element-count text | #115 expected-field list |
| --- | ---: | ---: | --- |
| CancelAction | 1 | 2 | `cancels`, `f` |
| CancelByCloidAction | 1 | 2 | `cancels`, `f` |
| BatchModifyAction | 1 | 2 | `modifies`, `a` |
| TwapOrderAction | 1 | 2 | `twap`, `details` |
| ReserveRequestWeightAction | 1 | 2 | `weight`, `destination` |

The new second names differ; this is not evidence of a single common frontend
flag. No meaning or concrete value type is assigned to `f`, `a`, `details` or
`destination`. These are field-list names and diagnostic counts, not proof that
two values are always required, an output serialization order, or a breaking
wire change. A one-field inferred model is not evidence for lossless handling
of the #115 structures.

The four relevant inferred handler declarations are retained under the pinned
`can1357-hl` commit `999556f6e0a474b8312db96ec3149e1c44e97c23`. They are labels/search
leads only; no implementation is copied, changed, compiled or executed. Their
file SHA-256 values, for identifying the exact source of the one-field leads:

| Handler file under `l1/exchange/handlers/` | SHA-256 |
| --- | --- |
| 02_batch_modify.rs | `ebdeb7237a905336f0b1e8f4d3e6348715b0e710eb718b9a92edef552edb6357` |
| 03_cancel.rs | `20423d44fe5d368e460c458bee138d94f7412ec3fd2fceeca4030ef84e0fe4ba` |
| 04_cancel_by_cloid.rs | `6964efe5e13d76a25025e9443c370af84d0cf402321d93e114a8ea88c8aff7d2` |
| 35_twap_order.rs | `cf8a088d536e8bcccb5220b2ebe59ec59a29431ad33ad68cf728d92af7a61452` |

No corresponding reconstructed ReserveRequestWeightAction declaration was located;
its comparison is based on the two captures, not an invented reference wrapper.

## Native range denominator

All twenty FDE-described owners are retained: **48,878 bytes / 9,869 decoded
instructions**. Each named diagnostic has two observed owner FDEs in each release.
This is an explicit export denominator, not an assertion of full semantic recovery,
provider identities or a one-to-one correspondence between the two owners.

| Release | Diagnostic type | Complete FDE half-open VA ranges | Bytes | Instructions |
| --- | --- | --- | ---: | ---: |
| 94 | CancelAction | `0x20c98e0..0x20c9ffd`<br>`0x2117760..0x2117d42` | 3327 | 690 |
| 94 | CancelByCloidAction | `0x20fadb0..0x20fb3b4`<br>`0x2118c00..0x2119342` | 3398 | 702 |
| 94 | BatchModifyAction | `0x20b2a60..0x20b3064`<br>`0x20e8dc0..0x20e9502` | 3398 | 702 |
| 94 | TwapOrderAction | `0x20f3910..0x20f3e1f`<br>`0x2143110..0x2143859` | 3160 | 620 |
| 94 | ReserveRequestWeightAction | `0x20ce9a0..0x20cede7`<br>`0x21421c0..0x214275c` | 2531 | 524 |
| 115 | CancelAction | `0x201c420..0x201d12d`<br>`0x206cd80..0x206d87b` | 6152 | 1251 |
| 115 | CancelByCloidAction | `0x2084540..0x2085047`<br>`0x20df4e0..0x20e01f4` | 6171 | 1273 |
| 115 | BatchModifyAction | `0x2024ca0..0x2025797`<br>`0x2075410..0x2076104` | 6123 | 1260 |
| 115 | TwapOrderAction | `0x2015360..0x20161a5`<br>`0x20eef60..0x20f00a1` | 8070 | 1533 |
| 115 | ReserveRequestWeightAction | `0x2072580..0x2073440`<br>`0x20bbd70..0x20bc844` | 6548 | 1314 |

## Binding the data to actual code

`spec.json` records exact coordinates derived from fully authenticated captures;
its SHA-256 is pinned in the collector. `records.json` retains body hashes,
file offsets, original FDE/CIE records and the exact diagnostic pointer/length
relocations. Each diagnostic has the complete `struct NAME with N element(s)`
text and an actual decoded LEA to its relocated fat-string record, inside each
listed owner FDE. These are referenced records, not an unqualified string census.

The four #115 field arrays begin at `0x6432af8`, `0x6450de8`, `0x643edf8` and
`0x64402c8`. The first is shared by the two cancel type names. Each row is a
16-byte pointer/length pair with a checked RELATIVE relocation, string address,
length and exact bytes. Twenty selected LEAs (two per #115 owner) select these
arrays. Their immediately following direct calls are bound by instruction bytes
and targets; a nearby MOV ECX,2 or MOV R8D,2 supplies the list length. Native
exports confirm the LEA, count-MOV and call instruction starts, not just raw
byte-pattern candidates. The consumer implementations remain unresolved; no
callee name or complete error formatting behavior is assumed.

The #94 compiler uses different/specialized setup for its single-field cases.
No corresponding #94 field-array LEA was established. The packet deliberately
does not manufacture old array addresses, infer an old unknown-field policy,
or equate a diagnostic count with accepted input grammar. The comparison is
between named diagnostic counts and separately bound #115 field-list arguments.

## Reproduce and controls

Python 3.12.14, macOS 26.4 arm64, GNU Binutils 2.47.20260726. From repo root:

```sh
python3 -B tools/action_field_drift.py --output work/action-field-drift-check
# Compare every generated file with this packet, excluding README/spec/manifest.
python3 -B -m unittest discover -s tests -p test_action_field_drift.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-014-action-field-drift && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates both entire input files before analysis/output, then
exports private byte-identical snapshots to readelf/objdump. Actual FDE endpoints
are independently confirmed by readelf, and complete objdump byte coverage is
checked with the existing decoder. Text outputs are written as UTF-8 bytes with
LF, without host newline translation. Original inputs are never modified.

Five focused tests check deterministic native regeneration and actual downstream
controls below the public hash gate: all ten diagnostic count characters, ten
count-MOV immediates across the #115 owners, eight field-name byte mutations at
four distinct arrays, four consumer call retargets, four real relocation changes,
four diagnostic LEAs and two actual FDE extent corruptions. Public entry also
rejects swapped, same-size corrupted and truncated captures before output creation.
These are artifact/metadata checks; no captured binary or emulator is executed.

## Results and limits

Observed checks: final focused five tests pass in 102.668 seconds. The required
full suite passes 436 tests in 249.614 seconds; doctor, signature/import verification,
catalogue check and reproduce pass. No hosted CI run is asserted.

No concrete action value layout, default/required-field behavior, nested value
parser, tuple/wire field order, complete unknown/duplicate-field policy, signing
payload, consensus acceptance, handler/API reachability or runtime equivalence
has been recovered. No Rust codec is implemented or measured. Allocation/drop/
unwind and helper closure remain unproved. The next question is to close the
new value-field decoders before defining a cross-release action codec.

No real action/request, signing key, wallet, network, chain or production file is
used. Captures/imports/source pins, generated catalogues and all progress gates
remain unchanged. Hosted CI is not claimed.

The question is distinct from #661's info-server settled-request visitors and
#37's source-path/FDE-gap release analysis. Existing #21/#226 dispatcher routing
and #242/#265 TWAP execution/result studies concern other #94 behavior; none is
claimed again as a new field-metadata finding. All five related action structures
are kept in this one packet rather than split into a PR per type.
