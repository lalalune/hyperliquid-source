# RE-001: map node115 exchange divisibility guard and payload handoff

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x5a6db30,0x5a6dd2f)`: 511 bytes.

Export denominator: **511 bytes /115 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The body reads N from the pointed state+0x28 and computes ror64(N*0xd288ce703afb7e91 mod2^64,4), requiring the result <=0x68db8bac710cb. These constants implement exactly unsigned divisibility by10000, including zero. The inverse of625 modulo2^64 is the multiplier; the accepted rotated value q is below2^60 and bounded by floor(UINT64_MAX/10000), so the modular relation gives N=10000*q without wrap. This is a mathematical interpretation of retained immediates, not execution of the target.

The input descriptor's min-i64 first word also rejects. Rejection writes an output min-i64 head and follows conditional cleanup; inactive fields of the sentinel form are not interpreted as valid allocation words. An eligible descriptor is copied128 bytes when the context byte equals1. Another transfer route requires state dword+0x10e8 equal1 and retained word+0x10f0 equalN; a lower old word reaches the actual diagnostic.

Other routes contain atomic reference/state operations and an opaque handoff. Their channel/queue meaning, synchronization guarantees, public value units and helper closure remain unknown. This closes only the eligibility arithmetic and observed payload transfer/rejection boundaries, without claiming a full exchange transition.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-exchange-divisibility-handoff/collect.py --output work/exchange-replay --check
python3 -m unittest discover -s tests -p test_twenty_exchange_static.py -v
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
