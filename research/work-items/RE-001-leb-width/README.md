# RE-001 tooling: reject unwind LEB values wider than 64 bits

Requirement: `fde_extents.py` explicitly accepts only the captured ELF64-LE
unwind encodings and must fail closed on malformed/unsupported records.
Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.

The previous continuation/shift check limited the number of bytes but did not
check the last payload's value. For example, unsigned `80` repeated nine times
followed by `02` returned 2^64. Signed `80` repeated nine times followed by `01`
returned 2^63. Both flowed through `parse_cie` as alignment values instead of
being rejected. This is an offline parser correctness defect, not a claim about
a captured target or runtime vulnerability.

The fix checks the decoded integer before returning: unsigned is in
0..2^64-1; signed is in -2^63..2^63-1. It preserves valid nonminimal encodings
within ten bytes, sign extension, valid endpoint values and consumed offsets.
It does not add a canonical-encoding policy. Existing truncation/continuation
rejection remains. No input, imported reference, dependency or gate changes.

Six regression tests exercise all 126 overflowing unsigned terminal bytes,
all 126 overflowing signed terminal bytes, endpoint/nonminimal values,
actual CIE-parser integration, truncation and excessive continuation. On the
base implementation, the same tests report 253 failed assertions; after the
fix all six pass. Original failure output is retained with local paths masked.

## Validation

Ubuntu24.04/WSL2, Python3.12.3. No target execution.

```text
python3 -m unittest discover -s tests -p test_fde_leb_width.py
make doctor verify test catalogue-check reproduce
```

The full required checks pass: 437 tests,151.089seconds. Analysis ready,
exact rebuild unavailable. Eight artifact identities,three signatures,
37 imports and seven reference pins verify unchanged.

The original and corrected `fde_extents(data)` results were also compared
directly for both fully authenticated inputs:

| Input | Bytes | SHA-256 | FDE records | Comparison |
|---|---:|---|---:|---|
| node94 | 91774280 | `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` | 121299 | all summary/extent/gap records equal |
| node115 | 105896032 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` | 135313 | all summary/extent/gap records equal |

`observed/comparison.json` retains result hashes and separate release identities.
This is equality of the offline parser's outputs, not reconstructed-node
equivalence. `observed/compare.py` contains the comparison method; point
`--base-tools` at an unmodified checkout of the stated base. Each input is
authenticated before either parser runs. Visor is not part of this comparison.

Raw `before.log` and `required-checks.log` mask only contributor checkout/tool
prefixes and normalize CRLF toLF. Source code and target bytes are unchanged.
No Rust build, complete function-boundary proof, runtime or hosted CI claim.
The next independent question is other unsupported DWARF encodings; this fix
does not broaden the parser's accepted encoding set.
