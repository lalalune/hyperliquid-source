# RE-001: map node115 bridge request selector and output construction

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x4526e40,0x45270f8)`: 696 bytes.

Export denominator: **696 bytes /137 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The incoming low EDX byte is retained as the selector. After opaque preparation and formatting/conversion, the converter at slot0x64e1060 receives mode2 if that byte equals3, and mode3 otherwise. A zero result byte reaches the actual bridge_request.rs:83:78 diagnostic; its nonreturn contract is not inferred from the name.

On the ordinary nonzero-result route, the body combines20 returned bytes with32 bytes from earlier preparation and calls0x4302cd0. The resulting pointer/length is handed to opaque digest slots0x64e0148 and0x64e0150, requesting32 output bytes. The digest algorithm and serialized content remain unclosed; no original signing or chain implementation is asserted.

The final output contains a one-byte allocation holding0x61 and native three-word descriptor (1,pointer,1), digest bytes at+0x18, and a word at+0x38 equal to0xa4b1 for selector3 or0x66eee otherwise. Bytes+0x40..+0x57 are zeroed. These are raw numeric values without assigning chain IDs or domain names. Helper errors, public selector validity and complete ownership remain unknown.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-bridge-selector-output/collect.py --output work/bridge_req-replay --check
python3 -m unittest discover -s tests -p test_twenty_bridge_req_static.py -v
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
