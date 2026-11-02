# RE-004: migrate the unsigned128 to binary64 value projection to node #115

- Component: foundation / compiler-builtins dependency attribution; no gate.
- Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Question: can the existing independently authored conversion be reused after
  retiring the earlier release from the working tree?
- Observation: the complete 132-byte leaf at ELF VA `0x63f00d0..0x63f0154`
  matches the published-artifact excerpt and the historical qualified body
  exactly, with no masks. The FDE has the same start and end and no LSDA.
- Interpretation: the retained register-only numerical proof applies to the
  same instruction sequence. Original nominal type, ABI and callers remain
  outside the migrated value-projection contract.

`records.json` pins the target, exact coordinates and historical source commit.
`node115.objdump` is the bounded GNU instruction export. `NUMERICAL-PROOF.md`,
the original artifact record, source provenance, license and frozen corpus are
preserved verbatim; their historical coordinates are context, not #115 addresses.
The old node, old implementation and unrelated research are removed from the
working tree and remain recoverable at the recorded commit.

## Reproduce

```sh
python3 tools/node115_u128_binary64.py --check --build-dir work/u128-binary64-check
```

The verifier checks the complete target digest before reading its exact FDE,
requires exact body equality, and rejects a changed body, changed bounds and
changed frozen inputs. The real standalone Cargo package has no dependencies.
The compiled Rust client receives input values only; expected output remains
outside the client. Compiler output, comparison totals and failure controls are
recorded under the selected ignored build directory.

This is one bounded semantic migration and one additional dependency comparison
window. It establishes neither first-party component completion nor whole-ELF
identity. The historical division and remainder candidates had no exact body
match in #115 and were not migrated by this check. Broader migrations require
their own target-specific evidence.

Fresh validation: **16,614 cases at both opt-level 0 and 3**, with zero
mismatches. Compiled exponent-bias and tie-parity mutants are rejected
(16,612 and 1,392 mismatches). `migration-validation.json` records this run.
