# RE-001: map node115 oracle selector guards and conversion result gate

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x2774760,0x277498f)`: 559 bytes.
- Complete FDE `[0x2357a10,0x2357cfd)`: 749 bytes.

Export denominator: **1308 bytes /283 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

This bounds the oracle-associated selection and conversion result gates, rather than claiming price units or full decimal conversion. The incoming unsigned key is divided by10000 through the retained reciprocal sequence. Its remainder first must fit the first row collection. The quotient must equal a second object's+0x50 word, and the same remainder must fit that object's length. The selected32-byte metadata row contributes a byte at+0x1d, required below7 before the later table access.

The subsequent floating calculation and helper0x5c43c60 use retained raw constant bytes, integer words, exponent/sign extraction and observed helper result flags. Raw constants are authenticated, but rounding, price units, decimal type semantics and the helper's algorithm are deliberately unclosed. In particular no whole float-to-decimal equivalence is asserted. Nonfinite bit patterns reach the local absent route; normal/subnormal/zero paths and helper flag branches remain in the complete export.

The ordinary present route copies16 local payload bytes to output+0x10, stores the original key at output+8 and qword1 at output+0. The absent route writes qword0 at output+0; inactive payload bytes are not assigned values. The actual caller is retained as context, without interpreting its full outcome. Invalid selection routes retain all three source Locations and opaque diagnostic contracts. The two lookup guards and result layout are native observations, not proof of caller-owned invariants or complete oracle behavior.

The retained complete caller contains the actual direct call at `0x2357a7e`; only that target binding is adopted, not its broader behavior or a recovered public ABI.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-oracle-selector-conversion/collect.py --output work/oracle2-replay --check
python3 -m unittest discover -s tests -p test_tnext_oracle2_static.py -v
```

Ubuntu24.04, Python3.12.3, GNU binutils2.42. The digest-first collector uses a
private non-executable input copy and checks complete FDE bounds, contiguous
native instruction bytes, raw unwind/LSDA records, actual calls/RELA slots and
source Location metadata. GNU text trailing spaces are trimmed only after raw
instruction verification. Original and mutated bytes are never executed or emulated.

The focused checks regenerate native records/exports exactly, reject a changed
target before native tools/output, and corrupt actual instruction groups and
semantic operands/conditions in private Python bytearrays. These are evidence
integrity controls, not equivalence of an invented source implementation.
No normalized or compiled source-body comparison is introduced.

All component gates remain false. No root Cargo graph, recovered public Rust ABI,
source-built node, complete helper closure, live fixture, captured execution,
network/chain action, signing or paid dataset is claimed. New material uses root
MIT; imported inputs retain existing rights. Remaining questions are explicit
above; the next step is to close the referenced opaque helpers and caller-owned
layouts before implementing any whole-component behavior.
