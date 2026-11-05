# RE-001: reconstruct the complete mixed-order threshold family

Assets allocation through an actual perp_meta.rs-associated caller; ownership
and source-level business role remain unproved. Sole node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
base05bc2de303c05525b71e7e257426e741bc66a390. This advances the complete
local scalar rule recorded statically by merged #2186/#2343/#2391; it is one
family contribution, not three alias or alternate-layout PRs.

| Family | Complete ELF VA | Bytes / instructions | B dwords / C qword |
|---|---|---|---|
|0|55ff9e0..55ffa44|100 /28|4294,4298,429c /4228|
|1|2c6f290..2c6f2f4|100 /28|4294,4298,429c /4228|
|2|55ff970..55ff9d4|100 /28|4e04,4e08,4e0c /4d98|

Total physical denominator300B84starts, all visited. There are two unique
complete encodings; family0/1 are exact aliases. proof.py authenticates all
three FDE/CIE/body records, full GNU/Capstone agreement, all local branches,
no calls/RIP dependencies, actual selected caller/sourceLocation, and an exact
whole100-byte encoding search at every.text byte offset. This is an exact
encoding census, not proof that no semantically equivalent bodies exist.

CONTRACT.md fixes the raw fields and memory premises. Signed firstu32-as-i32
then unsigned second/third fields form A/B's lexicographic order. A>=B and
T>=C returns2, taking precedence over fallback. Otherwise the result is whether
T>=saturating_u64_add(X,5000). Threshold equality is accepted, even atUINT64_MAX.
Only rawAL is compared; other registers/unknown objectpadding are not initialized
or invented. RealRET is required and any input write is rejected.

Native expectations come from actual instructions, not a source-level selector.
The corpus combines signed/unsigned boundaries, first-differing tuple positions,
threshold±1 and carry boundary values, primary threshold equality/precedence and
deterministic wide raw words. Every stimulus is measured independently at each
of the three entries under its actual memory layout. No fake helper, patched
code implementation or interior-state composition supplies an answer.

```sh
python3 research/work-items/RE-001-mixed-tuple-threshold-115/proof.py --objdump /path/to/objdump
python3 -m unittest discover -s tests -p test_mixed_tuple_threshold115.py -v
```

Actual-byte COW controls change numeric signedness, branch equality, threshold
carry/selection, field source and raw result, including separate observations
for each duplicate/alternate-layout body. Unknown-field and unknown-register
corruptions are rejected. Expectations/native/contract must be Git-sealed before
independent Rust. No captured ELF process, Unicorn, original compiler recipe,
Linux execution, original API/ABI, units/financial policy, byte equivalence or
whole-component acceptance is claimed. All92 gates/byte registrations unchanged;
oldpackets/imports/captures/tools preserved. New source MIT, no unlicensed code.
Next: recover caller object provenance and uses of rawAL before assigning policy.

## Independent source and replay

Pre-Rust sealb028a9e5f0353ddfad68146974d2d70a79ee1a1d contains no owned
Rust source. Native freeze43.631s produced17847 distinct family/input rows
(5949at each entry); pre-Rust7focused tests passed5.707s. Independent safe
no_std source uses Rust mixed-sign tuple ordering and saturating_add, instead
of transplanting the native register/carry sequence. One source API takes the
raw logical fields; target-specific layouts are independently materialized by
the native evaluator. The transport family coordinate chooses the original
measurement, not a different Rust algorithm or invented original ABI.

```sh
python3 research/work-items/RE-001-mixed-tuple-threshold-115/verify-rust.py \
  --rustc /path/to/rustc --out /fresh/owned/output
```

Actual original opt0/3 and repeat match all17847 rows. Same-path opt3 rlib bytes
repeat. The186case fixture only selects sealed observations. Twelve compiled
wrong sources emit complete streams and fail ordinary assertions101; crashes
are not accepted. Build/control run179.501s passed. Large tables/full receipts,
15comparisonstreams and152stdout/stderr logs are losslessly gzip archived;
only owned path prefixes in command logs are projected. Exact SHA-checked
client source is rehydrated before builds, with actual build/compare function
ASTs unchanged. Source/driver/fixture/input/gold hashes are in rust-results.json.
See VALIDATION.md for full command results and limits. Nothing advances a gate.
