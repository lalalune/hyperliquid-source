# RE-014: two settled-request struct visitors differ between #94 and #115

- Component: API/serialization release drift, bounded RE-001 range evidence.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes).
- #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes).
- Question: may the inferred one-field SettledOutcome/SettledQuestion shapes be applied unchanged to both captures?
- Answer: no such cross-release assumption is supported. Both diagnostic cardinalities change from one to two, and the selected #115 decoder bodies recognize `only_use_db` in addition to the identifier field.
- No component gate, complete codec or public endpoint reachability claim.

## Scope and prior work

The pinned inferred `info_server/request.rs` declares one field for each variant.
It is an unlicensed search lead, not implementation authority. Reference pin:
`can1357-hl` commit `999556f6e0a474b8312db96ec3149e1c44e97c23`,
request.rs SHA-256 `059084c64ed4ddbf397189959ccbb43a4cbe898c037d64217f3516061d0e7696`.
No code from it is copied or changed. This packet establishes a specific
cross-release difference instead of assuming a single reference shape fits both.

Merged #27 maps the #94 request hub/tag anchors; open #188 hardens its verifier.
Open #37 compares release source-path/FDE gaps. Neither establishes the #115
settled-variant field handling described here. The current packet does not
reopen their hub, path ownership or gap classification claims. Both related
variants are kept together; no PR per variant/release.

## Complete native export denominator

| Release / diagnostic name | Actual FDE half-open VA range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| #94 SettledOutcome | `0x2051140..0x20519b4` | 2164 | 467 |
| #94 SettledQuestion | `0x2076950..0x20771c4` | 2164 | 467 |
| #115 SettledOutcome | `0x1fb7530..0x1fb81dd` | 3245 | 686 |
| #115 SettledQuestion | `0x1fc5470..0x1fc611d` | 3245 | 678 |

Total: **10,818 bytes / 2,298 decoded instructions**. All four complete bodies,
raw FDE/CIE records, coordinates and SHA-256 values are retained. Exporting
complete bodies is not recovery of every input branch, call or Rust type.

## Diagnostic binding, beyond an unreferenced string search

The named diagnostic strings are reached through actual RELATIVE relocations in
16-byte pointer/length records, and decoded LEAs select those records inside the
listed FDEs. The explicit string length is checked; the final plural `s` in #115
is part of the record.

| Release / variant | Diagnostic VA | Pointer/length slot | LEA site | Count text |
| --- | --- | --- | --- | --- |
| #94 Outcome | `0x3d1e6f` | `0x569abf0` | `0x2051210` | `with 1 element` |
| #94 Question | `0x3d1eac` | `0x569ac00` | `0x2076a20` | `with 1 element` |
| #115 Outcome | `0x5e5755` | `0x642b238` | `0x1fb75fe` | `with 2 elements` |
| #115 Question | `0x5e5a72` | `0x642b308` | `0x1fc553e` | `with 2 elements` |

Each full string begins `struct variant NodeInfoRequest::` and then the named
variant. Their relationship to similarly named inferred types is a source-label
inference. The target diagnostic/call data provides the independent observation.
A diagnostic field count alone does not establish which fields are required.

## Additional #115 field selector and local flag state

The Outcome function has selected string/byte comparison arms that first require
length 11, then compare overlapping qwords `[0,8)` and `[3,11)`. Their constants
are little-endian `0x6573755f796c6e6f` and `0x62645f6573755f79`. The five overlapped
bytes agree; their union spells exactly **`only_use_db`**. The selected Question
comparison uses the same two constants. `records.json` binds four actual
MOVABS pairs. Additional bytewise comparison arms are visible in the raw exports;
this packet does not count them as separate recovered parsers.

The selected Outcome equality arm sets local key tag 1 at `0x1fb7948`; the unknown
key arm sets 2 at `0x1fb7990`. At `0x1fb79ae..0x1fb79bc`, tag 2 takes another
path, tag 1 checks R13B against its initial sentinel 2, and the field-value path
loads a byte into R13D at `0x1fb7a05`. Other tags follow the identifier path.
The Question body has corresponding field/flag obligations, retained in full.
The identifier comparisons distinguish `outcome` (7 bytes) / `question` (8 bytes)
from this new 11-byte field name. No enum-wide wire tag mapping is claimed.

Both #115 bodies initialize R13B to 2, and a selected normal map-result path
applies `AND 1` then stores R13B at output `+0x10`. The local cases 0/1/2 therefore
map to 0/1/0 at that store; the untouched sentinel becomes zero on this path.
This is compatible with a default-false flag, but the concrete Rust boolean/option
layout and full parser admission are not independently recovered. The one-element
sequence route also has an explicit zero-byte store in the retained exports.
Do not infer from the text count that a second field must always be supplied.

## What the comparison does not establish

- No assertion that a live HTTP endpoint accepts a particular JSON document.
- No complete #94 unknown-field policy: the #94 key-decoder helpers are not closed.
- No implementation of JSON/MessagePack parsing, required/duplicate-field errors,
  entire serde Content layout, nested identifier parser or caller/type closure.
- No public API removal/addition census from which other diagnostics are present.
- No allocation/drop/unwind equivalence, server startup or captured execution.

These are variant-local observations and a release-specific reconstruction
constraint. Their practical implication is to preserve separate #94/#115 field
models until the remaining decoder/caller obligations have been validated.

## Reproduce

Python 3.12.14 / macOS 26.4 arm64 / GNU readelf and objdump 2.47.20260726.
From repository root, with both pinned LFS captures materialized:

```sh
python3 -B tools/request_variant_drift.py --output work/request-variant-drift-check
# Compare every generated file with this packet, excluding README/manifest.
python3 -B -m unittest discover -s tests -p test_request_variant_drift.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-014-settled-request-fields && shasum -a 256 -c MANIFEST.sha256)
```

The producer reads and authenticates both complete captures before analysis or
output creation, then exports byte-identical private snapshots to GNU tools.
Actual FDE extents are independently checked with readelf; all objdump bytes and
selected instruction starts are checked with the existing export decoder.
Tests compare deterministic regeneration, all 2,805 non-identity single-byte
key substitutions plus all 0..32 lengths, and the byte-coverage proof that the
two overlapping comparisons constrain every byte of an arbitrary 11-byte key.
These are conditional equality obligations, not target/emulator execution.
Real key-immediate, selector/flag, diagnostic, relocation, LEA and FDE mutations
exercise checks below the public identity gate. Same-size corrupted and swapped/truncated release inputs
are rejected before an output directory is created.

Observed validation: final focused five tests pass in 73.418 seconds; required
full suite passes 436 tests in 225.492 seconds. Doctor, signature/import verification,
catalogue check and reproduce all pass. The manifest/diff checks pass as well.

Captured originals, imports, source pins and generated catalogue/progress files
are preserved. No runtime request, network, wallet or chain operation is used.
All component gates remain false; hosted CI is not claimed.
