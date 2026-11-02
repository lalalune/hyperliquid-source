# RE-002: source-build correspondence for the node94 field-fold leaf

- Component: foundation, RE-002 dependency provenance, supporting RE-004.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline: `d3af75257a396c85d20857f421c370ddb8cb40e5`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  no inferred implementation is copied or used to validate the result.
- Bounded question: does the mapped five-word folding leaf correspond to a
  public secp256k1 field routine, and under which assumptions is it a
  reduction modulo that field's prime?
- Claim status: observed raw source-build correspondence; proved numerical
  identity under explicit assumptions; unresolved historical source/compiler
  selection and caller invariants.
- Intended files: this packet only. No milestone or byte-registry edits.

The complete **123/123 bytes** at ELF VA `[0x56327f0,0x563286b)` match an
isolated compilation of the public
[`rustsecp256k1_v0_10_0_fe_impl_normalize_weak`](https://github.com/rust-bitcoin/rust-secp256k1/blob/6648126c69ce8056d053cbaa22246d12c76f3fc1/secp256k1-sys/depend/secp256k1/src/field_5x52_impl.h)
function. Two independent
GCC 13.3 object builds are byte-identical. Neither comparison normalizes
operands, removes a prefix, or transplants target code into a build.

The prior [mapping](../foundation-multi-limb-multiply-accumulate-94/README.md)
established this function's bytes, FDE and three direct callers. The prior
[Rust reconstruction](../RE-004-node94-limb-fold-rust/README.md) established
its numeric recurrence over arbitrary five-u64 inputs but explicitly left
the field modulus, source function and cryptographic meaning unknown.
This packet supplies a licensed named-source compilation witness and a
bounded field interpretation. Those earlier results remain unchanged.

## Source and exact build scope

The #94 inventory lists `secp256k1 0.29.0` and `secp256k1-sys 0.10.0`.
That is a dependency lead, not source identity by itself. The public
`rust-bitcoin/rust-secp256k1` tag `secp256k1-0.29.0` resolves through tag
object `320b877a07c70acafbffe7498bb5516f02eeead3` to immutable commit
`6648126c69ce8056d053cbaa22246d12c76f3fc1`.

[SOURCES.json](SOURCES.json) binds five complete upstream files to that
commit's Git tree, Git blob IDs, lengths and SHA-256 values. `third_party/`
preserves their notices and unmodified `COPYING`. These are public MIT
secp256k1 sources, not the unlicensed inferred reference tree.

The compilation unit selects one unchanged function from
`field_5x52_impl.h`, includes the unchanged `field_5x52.h` type definition,
and selects the actual non-VERIFY expansions of `VERIFY_CHECK` and
`SECP256K1_FE_VERIFY_FIELDS` witnessed in `util.h` and `field.h`.
It does not replace a callee or invent a field representation. The empty
macros implement the public non-VERIFY configuration; they are not a claim
that every original node object used that configuration.

The complete build command, in each fresh build directory, is:

```sh
gcc -std=c99 -O2 -fcf-protection=none -fkeep-static-functions \
  -c probe.c -o probe.o
```

`-fkeep-static-functions` materializes the selected static function for
inspection. GCC 13.3.0, target `x86_64-linux-gnu`, emits a local FUNC that
covers the entire allocated executable `.text` section. Its 123 bytes have
SHA-256 `2e413a86c8670e24e30144a0d9281fc2ed3a470d6772ed9cd53def98b4c6ecaa`.
There are no code relocations, helper calls or static-data references.
Object unwind relocations are retained separately and are not masked code.
The public function returns `void`; both compiled bodies incidentally leave
the input base pointer in RAX while using it for stores. That register value
does not establish a pointer-valued source return type or recover the caller ABI.

This is a bounded C source-compilation witness. It is not a full secp crate
build, a new Rust implementation, a recovered node build, an original GCC
version/flag identification, or proof of unique historical source origin.
The existing independently authored Rust component retains its own build
scope, ABI limits and all-u64 wrapping semantics.

## Target admission and controls

The collector admits the full #94 digest and reruns the existing static
mapping checker before comparing any bytes. It resolves the code through
both the executable section and PT_LOAD mapping. The prior checker locks
FDE `[0x56327f0,0x563286b)`, the next FDE, five trailing `int3` bytes,
instructions, no-call rule, relocation result and the direct-call witnesses
at `0x563b803`, `0x563bc5f`, `0x5640242`. No new complete xref census is claimed.

`observed/record.json` retains full raw comparison differences and object
identities. Two separately compiled counterfactuals must fail:

- `-fcf-protection=branch` emits a 127-byte body, including `endbr64`.
  All bytes and the unequal extent are retained; its prefix is not removed.
- Changing the public fold coefficient from `0x1000003d1` to
  `0x1000003d0` produces a normal object whose code fails raw comparison.

An actual full-target byte corruption must fail digest admission and also
fail an unmasked byte comparison beyond the identity guard. These controls
do not receive authentic target provenance. The compiler and generated code
are never used to execute captured instructions; no compiled function is
executed either.

## Field interpretation

The [proof](PROOF.md) starts from the native equations, the public five-limb
representation and explicit magnitude bounds `0<=m<=32`. It proves
`N(output)=N(input)-(input[4]>>48)*p`, with
`p=2^256-2^32-977`, and checks that no intermediate u64 addition wraps on
that domain. This supplies a qualified purpose for the literal constant.
It does not prove that the three callers satisfy those magnitude bounds.
The numeric argument inherits the earlier packet's ordinary readable/writable
40-byte region and valid call/return assumptions; it makes no fault or
aliasing claim.

Two load-bearing limits are retained as controls: representing exactly `p`
returns `p`, so this is not canonical normalization; arbitrary oversized
u64 limbs can wrap and violate modular congruence, even though the existing
Rust numeric reconstruction correctly preserves those machine equations.
The 160 finite corner checks support the written bound proof, not an
exhaustive input or target-execution claim.

The optional [solver proof](prove.py), using `z3-solver==4.15.4.0`, also
returns **UNSAT** for any difference from the exact field identity or
output bounds over the entire stated domain. Its 320-bit integer embeddings
cannot overflow for five u64 limbs. Removing the magnitude bounds returns
**SAT**, with an integer-replayed counterexample retained in
`observed/field-proof.json`. This qualifies the admitted equations; it does
not independently prove caller preconditions or the research compiler.

## Reproduce and remaining gaps

From the repository root, with pinned artifacts and submodules materialized:

```sh
python3 research/work-items/RE-002-secp-field-normalize-weak-94/collect.py \
  --binary artifacts/node/94/hl-node --gcc /usr/bin/gcc \
  --output work/new-secp-field-witness
objdump -dr -Mintel work/new-secp-field-witness/build-a/probe.o
objdump -d -Mintel --start-address=0x56327f0 --stop-address=0x5632870 \
  artifacts/node/94/hl-node
python3 tools/foundation_multi_limb_multiply_accumulate.py \
  --check research/work-items/foundation-multi-limb-multiply-accumulate-94/evidence.json
python3 research/work-items/RE-002-secp-field-normalize-weak-94/prove.py \
  --output work/new-secp-field-proof.json
make doctor
make verify test catalogue-check
make reproduce
```

The collector has no download path and executes only the compiler/its version
query. Raw objects, translation units and build streams stay in ignored
`work/`; compact records and disassembly are retained here. A different
compiler may legitimately produce a negative comparison; no alternate
source candidate or normalization is silently substituted.

Actual results are retained in [VALIDATION.json](VALIDATION.json).
`make doctor`, `make verify`, `make catalogue-check` and `make reproduce`
passed. The complete `make test` attempted all 957 modules and exited
nonzero for one initial missing-Capstone import error. After installing its
documented dependency, that module passed all nine tests. Three early
missing-capture modules subsequently passed all 98 tests on retry.
Seventy skipped outcomes remain for the recorded fixture, provider,
archive, platform and captured-execution conditions. This is not a pristine
full-suite pass. Post-suite input verification and catalogue checks passed.
Verbatim upstream source and GNU exports retain their original whitespace;
the primary analysis/documentation whitespace check passes.

All full-component gates remain false. No generated progress, catalogue or
reviewed comparison registry is changed. The denominator is one admitted
123-byte helper, not all foundation code or a whole-node function census.
Original caller invariants, dependency-version uniqueness, complete ABI,
link/data/unwind identity and whole-ELF equivalence remain open. Next,
qualify the field representation and magnitude transitions at a caller.
