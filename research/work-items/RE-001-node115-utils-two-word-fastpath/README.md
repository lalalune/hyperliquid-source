# RE-001: map node115 utility identity fast path and fallback handoff

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x38d7f20,0x38d80f7)`: 471 bytes.
- Complete FDE `[0x22ed1f0,0x22ed70a)`: 1306 bytes.

Export denominator: **1777 bytes /381 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

The question is exactly which metadata words permit the utility's fast return, and which work is skipped. The body calls the helper bound through0x64e0930 for the first input pair, requiring local dword tag!=2; it saves the words at local+0x68/+0x70. It repeats that helper for the second input pair and requires its tag!=2. Equality of BOTH retained words returns EAX=0 immediately, without the later fallback preparation/handoff.

These fields are raw two-word identities: no device/inode, time/size, pathname or public metadata type is inferred. A tag2 result instead follows a dynamic error route through0x4303420 and a further indirect call, whose complete contract is unclosed. If that route returns, local control can continue to the fallback; no safe error rejection is fabricated.

For unequal ordinary results the body invokes preparation/format/conversion helpers and passes a new pointer/length pair with the first input to slot0x64e9560. A zero result proceeds to slot0x64e0028 on the second input; a further zero reaches slot0x64e0a00 with the actual utils.rs:121:5 Location. Nonzero results take the observed dynamic error routes. Native ownership/cleanup branches are retained, but helper internals and filesystem/network effects are unmeasured. No operations are executed; this is static handoff/shortcut evidence, not an operational copy or safety claim.

The retained complete caller contains the actual indirect call at `0x22ed339`; only that target binding is adopted, not its broader behavior or a recovered public ABI.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-utils-two-word-fastpath/collect.py --output work/utils-replay --check
python3 -m unittest discover -s tests -p test_tnext_utils_static.py -v
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
