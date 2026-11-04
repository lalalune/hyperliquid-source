# RE-001: map node115 vault identity-policy entry guards

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static research; no inferred source was copied.

- Complete FDE `[0x44ae810,0x44af2e1)`: 2769 bytes /606 instructions.

Export denominator: **2769 bytes /606 instructions**.
These are evidence extents, not recovered or compiled-comparison coverage.

## Question and scope

Which ordered identity-policy guards run at entry to the vault-associated body,
and which raw rejection reasons reach its shared early return? Only these entry
conditions are interpreted. The complete FDE is retained for boundaries and
context; its subsequent lookup, amount changes and later outcome are unclosed.

The local incoming convention uses output RDI, context RSI and an identity-byte
pointer RDX. The context's qword+0 is retained in R15. Valid native objects and
extent invariants are assumed; no public Rust ABI or original policy names are
assigned. This is ordinary reconstruction evidence, not a vulnerability claim.

## Full20-byte comparison and ordered gates

The stored identity spans context offsets **+0xa0..+0xb4**, half-open. Each
comparison loads16 bytes plus a4-byte tail from the incoming identity and from
that stored range. MOVD zeroes upper lanes for the tail comparison. PCMPEQB,
PAND, PMOVMSKB and a0xffff comparison require ALL20 bytes to match; a16-byte
prefix alone is insufficient. The comparison is byte equality, not a proven
address, hash algorithm or ownership model.

1. At0x44ae82d, context qword+0 is compared with exactly1. Only that raw value
   enters the first comparison. A mismatch writes reason word **0x16** at
   output+0x10 and jumps to0x44aef30. This occurs before the second gate.
2. Otherwise the byte at context+0xb5 is tested against0. A NONZERO byte skips
   the second comparison; it is not tested for equality with1. A zero byte
   enters the same full20-byte comparison. Mismatch writes reason **0x17**
   at output+0x10, then reaches the same early-result path.
3. A matching identity passes both entry tests. On raw contexts outside the
   first tag1 case, a nonzero policy byte also skips both identity requirements.
   Equivalently the measured prelude continues for `equal20 || (mode!=1 &&
   policy_byte!=0)`. This local raw predicate is not a claim that arbitrary mode
   encodings are valid source variants or that passing it accepts the operation.

If both restrictions would reject, **0x16 takes priority** because the first
mismatch exits before the policy-byte test. At0x44aef30 the shared failure path
writes qword **0x8000000000000019** at output+0 and jumps directly to the
common epilogue. Output+8 and other inactive bytes are not assigned values here.
The raw head/reason encodings are not given global result-enum names.

The prelude has no helper call: its failure paths store through the output
pointer and local stack, then return. The first helper call after both gates
is0x44a9430 at0x44ae909. This describes concrete store/call ordering, not an
aliasing guarantee if callers supplied overlapping pointers. Passing the prelude
is not full admission, success, transfer completion or proof of a security issue.

## Source attribution and remaining work

A real LEA within this same complete FDE at0x44af2ad binds the retained
`l1/src/vault/mod.rs:401:58` Location. That establishes bounded source
association; it does not recover an original function name or close the other
paths of this2769-byte body. Other diagnostics and helper calls remain in the
full export without being adopted as measured behavior.

The next step is to bind caller-owned policy/identity fields and then close the
post-prelude operation separately. The ordered gates must be preserved during
that reconstruction, without treating these local flags as a new public API.

## Reproduction and negative controls

Linux Python3.12.3 and GNU binutils2.42; no target execution or emulation:

```sh
python3 research/work-items/RE-001-node115-vault-entry-guards/collect.py --output work/vault-replay --check
python3 -m unittest discover -s tests -p test_four_vault_static.py -v
```

The collector authenticates the complete target before any native command or
output, uses a private non-executable copy, agrees on complete unwind ranges
and relocation records with independent readelf, and verifies contiguous native
instruction bytes. Full original bodies, raw FDE/CIE, LSDA coordinates, every
measured direct/RIP call and source Location binding are retained. Text exports
trim trailing whitespace only after instruction-byte validation.

5 focused tests cover original anchors, exact export regeneration, wrong
artifact identity rejection before output, independent corruption of all claim
anchor groups and mutations of actual semantic sites. The dedicated sites
change the raw tag/condition, field displacement, arithmetic or callback/result
branch relevant to this question. Changes occur only in private Python arrays;
neither original nor altered instructions are executed or emulated.

All component gates remain false. No root Cargo graph, source-built node, binary
equivalence, complete original Rust types, protocol execution, signing, chain
action, paid dataset or live user fixture is introduced. New code/analysis is
root MIT; imported artifacts retain their existing terms. Full repository checks
and generated inventory integration are recorded with the final submitted head.
