# RE-001: equal-length adapters and zipped record layout

- Component: foundation / collection ownership support. Question: what input
  descriptors, allocation bound and output byte order do the two zip paths use?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead only.
- Status: instruction/store observations and valid-buffer/count models.
  Original element types, allocator/drop behavior and portable Rust ABI unknown.

## Reproduce

Repository root with CPython 3.12.14 on Windows:

```sh
python tools/zip_records_static.py --out work/zipped-record-layout-94.json
python -m unittest discover -s tests -p test_zip_records_static.py -v
python research/work-items/RE-001-zipped-record-layout-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
Captured code and native allocator calls never execute.

Complete retained FDE windows:

| Start..end exclusive | Bytes | Instructions | Role |
| --- | ---: | ---: | --- |
| `0x28315f0..0x28316ca` | 218 | 60 | Adapter A |
| `0x471e100..0x471e1e0` | 224 | 61 | Adapter B |
| `0x2519c60..0x2519eae` | 590 | 144 | Collector A |
| `0x47f8e70..0x47f9174` | 772 | 189 | Collector B |

Total **1,804 bytes / 454 instructions**, with contiguous complete byte
consumption, raw original FDE/CIE records and body hashes. Selected observations
are instruction starts. Coordinates are ELF VAs; `.text` offsets are VA minus
`0x1000`. No masks. All related copies are in this single packet.

## Adapter descriptors and copy observations

Both adapters compare input header lengths at offset `0x10`; unequal values
reach a source-bound assertion followed by UD2. Location records `0x56c4f80`
and `0x572e878` resolve to `base/src/u.rs:101:9`. The shared assertion slot
`0x576e2b8` resolves to `0x157b5e3`. Header words at 0 and 8 are passed as
capacity/pointer candidates; that interpretation is local, not a portable Vec ABI.

Equal lengths construct an 80-byte iterator descriptor: left start/current,
capacity and end, then right start/current, capacity and end, then two zero
words. Ends advance by **40*n** and **24*n** respectively. Actual direct calls
bind adapter A to collector A, and adapter B to collector B.

The collectors recover remaining counts by subtracting current from end,
shifting right three and multiplying modulo u64 by inverse-5 or inverse-3.
For valid strided ranges, `(5 * 0xcccccccccccccccd) mod 2**64 = 1` and
`(3 * 0xaaaaaaaaaaaaaaab) mod 2**64 = 1`, so this recovers their element counts.
The collectors select the smaller remaining count; the adapters' equal-length
valid-buffer domain makes them equal. Arbitrary malformed pointers are outside
the model.

For each output row, captured stores copy left bytes `[0,40)` followed by right
bytes `[0,24)`, into output `[0,40)` and `[40,64)`. Output stride is 64. The
byte model follows the actual 16+16+8 and 8+16 store groups and is independently
compared with eight-qword record expectations. No source tuple field layout or
semantic element names are invented from these offsets.

## Allocation bound and limits

The selected allocation guard rejects when `(n >> 58) != 0` or when the
wrapped u64 `n << 6` exceeds `2**63 - 8`. It admits counts at most
**`2**57 - 1`**. For n below `2**58`, the scale does not wrap and the comparison
gives that bound; larger n is rejected by the first test. This is integer guard
reasoning, not an actual large allocation. Empty paths use dangling pointer
word 8 with zero count. OOM, alignment contracts, complete cleanup and unwind
semantics remain unresolved; they differ between the two collectors' helpers.

The reference `base/u.rs` suggests a generic equal-length zip; this packet adds
target-bound descriptor/collector details without copying its implementation
or declaring its generic Rust types recovered.

## Controls and required checks

Six focused methods pass. All 64 one-hot byte positions preserve their output
positions. Record-array lengths 0..128 agree with an independent eight-qword
construction. Count recovery is checked at 4,096 low counts plus two upper
nonwrapping boundary counts per stride; allocation guard probes cover low
counts and both shift/isize boundaries. These are model/primitive populations,
not native heap tests or exhaustive valid Rust objects.

Actual-capture mutations cover length checks, strides, modular inverses,
allocation guards, copy offsets, collector calls, both source records, all four
FDE extents and identity. Make is absent; required Makefile Python commands were run directly. Full suite:
**363 tests in 107.219 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. This independent main-based branch excludes unmerged #227. Doctor
reports missing native prerequisites. Eight artifact size/digest checks pass
before missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. Those failures are not marked passed.

No complete Rust layout, arbitrary-pointer behavior, allocator/drop/unwind
closure, native build/equivalence, imported change, hosted CI or progress gate.
Next question: close the collector-specific cleanup helpers and typed callers
before reconstructing ownership end to end.
