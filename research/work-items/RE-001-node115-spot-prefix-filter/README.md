# RE-001: map node115 spot output prefix and overflow early stop

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x3d5e540,0x3d5e817)`: 727 bytes.
- Complete FDE `[0x3bfd3c0,0x3bfdb3c)`: 1916 bytes.

Export denominator: **2643 bytes /552 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

This maps the post-conversion filtering/store boundary and resulting prefix, not full financial scaling. The input cursor visits32-byte rows and produces an in-place selected prefix at the original base. Native ratio/conversion instructions and their raw constants are retained, but price/size units, exact numeric conversion semantics and original policy are unclosed. Their unsigned candidate word in R15 is the boundary used below.

Candidate<threshold skips the row without advancing the output cursor. Candidate>=threshold first attempts unsigned addition to the pointed aggregate. No carry stores the new aggregate, copies the row's first24 bytes plus candidate at+0x18 into the output prefix, and advances the output pointer by32. Thus successful rows retain source order and the converted amount replaces the final word; this is not a new allocation.

Carry branches BEFORE the aggregate store and BEFORE copying the current row. It conditionally invokes the existing-result cleanup, writes raw reason0x109 and retained error payload/candidate, then exits traversal. Prior successful row/aggregate writes are not rolled back. The output descriptor still reports the preserved allocation/base and the successfully written prefix length `(write-base)>>5`. Empty input returns a zero-length prefix. Caller, helpers, raw constants and source Location are retained, while payload padding and result-enum names are not invented. No vulnerability or atomicity claim is made.

The retained complete caller contains the actual direct call at `0x3bfd4d6`; only that target binding is adopted, not its broader behavior or a recovered public ABI.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-spot-prefix-filter/collect.py --output work/spot-replay --check
python3 -m unittest discover -s tests -p test_tnext_spot_static.py -v
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
