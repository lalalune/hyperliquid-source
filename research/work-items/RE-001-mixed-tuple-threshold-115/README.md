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
