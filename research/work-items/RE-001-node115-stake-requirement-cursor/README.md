# RE-001: map node115 stake-requirement cursor bounds and item tags

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x294ceb0,0x294cfbe)`: 270 bytes.
- Complete FDE `[0x235a050,0x235a26e)`: 542 bytes.

Export denominator: **812 bytes /209 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

This bounds the iterator-like control state used by a stake-requirement-associated caller. It does not recover the requirement calculation or original types. On valid native objects, let i be the unsigned word at input+0x20 and o the word at +0x28.

The body forms i+1 and diagnoses wrap to zero, then forms o+(i+1) and diagnoses unsigned carry. Both guard routes precede the cursor store; the diagnostic's complete nonreturn contract is unclosed, so this is not a proved safe rejection API. If total>=5, the cursor is stored as 4; otherwise it stores i+1. It returns raw AL=2 when old i>=4 OR total>=5. Thus the stored cursor can advance on a terminal return, and a terminal payload in RDX is the old index rather than a yielded requirement.

On the yielding route, old i is necessarily below4. The byte comparison against old i's low byte supplies a 0/1 increment to opaque helper `0x2c58c70`'s result. That unsigned addition saturates to UINT64_MAX on carry. A signed-relative data lookup indexed by old i and a secondary byte selects the multiplier used by MUL. The data table contents, secondary byte's validity bounds, selected values, helper result and requirement units are deliberately UNMEASURED here; no table extent or valid enum range is invented.

No product overflow leads to AL=1 and product in RDX, after the local cleanup-shaped call. Product overflow instead conditionally cleans the result addressed by the saved incoming RDX, writes raw word 0xc5 to it, and returns AL=0; RDX on that route is not claimed as a yielded product. The cleanup helper contract remains open.

The actual caller invokes this body at `0x235a070` and `0x235a168`, tests AL bit0, and appends RDX only on that bit. AL=0 and AL=2 therefore both terminate its item-consumption branch, with error detail retained separately. The full caller is retained only as context. Actual Location LEAs bind both bodies to `l1/src/exchange/stake_requirement.rs:5:62`.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-stake-requirement-cursor/collect.py --output work/stake-replay --check
python3 -m unittest discover -s tests -p test_next4_stake_static.py -v
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
