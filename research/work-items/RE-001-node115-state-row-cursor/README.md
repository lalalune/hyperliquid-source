# RE-001: map node115 state row cursor and sentinel termination

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x229b760,0x229b88e)`: 302 bytes.
- Complete FDE `[0x231f5e0,0x231f71f)`: 319 bytes.

Export denominator: **621 bytes /159 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

The question is whether a sentinel row is skipped or terminates the local state-associated traversal, and when the cursor advances. RDI is output, RSI the cursor descriptor. Valid native objects and extents are assumed; no public Rust ABI or state schema is recovered.

The cursor words at +0 and +8 are compared. Equality writes only `0x8000000000000000` at output+8 and returns. Otherwise the code advances cursor+0 by 32 BEFORE loading/checking the selected row's +8 word. A sentinel there reaches the same result and returns immediately; this is not a loop that skips sentinel rows. Other inactive output bytes are unspecified.

For an ordinary row, row+0 supplies a pointer and row+0x10 supplies 16 copied bytes. The pointer's +0x10 word must equal row+0x18; mismatch calls the Location-associated diagnostic then reaches UD2 on local fallthrough. Equality prepares a bounded value passed in RSI (the local unsigned min, equal under this gate), a descriptor and the opaque helper `0x2ccda40`. After normal helper return its three output words are copied to output+8/+0x10/+0x18, and the row pointer to output+0. Projection, allocation, cleanup and helper semantics remain unclosed.

The actual call at `0x231f638` consumes this output. Its zero-minus-output+8 comparison uses JO to terminate on the min-i64 sentinel; otherwise it copies a 32-byte result into the destination and increments its length under its separate capacity check. Cleanup and broad state ownership are not interpreted. The complete caller is retained, not claimed fully recovered.

Source association comes from the actual LEA at `0x229b841` to `l1/src/abci/state.rs:340:21`. No persistence, serialization, state-root or valid-collection policy is inferred.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-state-row-cursor/collect.py --output work/state-replay --check
python3 -m unittest discover -s tests -p test_next4_state_static.py -v
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
