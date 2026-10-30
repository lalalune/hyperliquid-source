# RE-002: report the explicitly selected Ghidra directory

- Component: foundation, analysis-tool provenance support only.
- Question: does the read-only doctor report the Ghidra directory selected by
  `GHIDRA_INSTALL_DIR`, as documented for the REA launcher?
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: `can1357/hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  no inferred reference implementation is copied or interpreted in this change.
- Target context: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
  Its 91,774,280-byte captured file was materialized and checked against
  `provenance/artifacts.json`; this is a digest check, not signature verification.
- Claim status: observed configuration/reporting defect. No component gate.

## Source evidence

`docs/REA.md` documents `GHIDRA_INSTALL_DIR` and says explicit values are
preserved. `tools/rea.py:environment()` likewise preserves that variable.
The baseline `tools/doctor.py:locate_ghidra()` considers only the legacy
`GHIDRA_HOME` and automatic workstation discovery. It can report an explicitly
selected installation as absent, or report an unrelated installation instead.

The fix checks `GHIDRA_INSTALL_DIR` first. An invalid explicit directory is
reported unavailable, rather than silently selecting another provider. When
the variable is unset or empty, the legacy and automatic paths retain their
existing behavior. No launcher, provider registration or user configuration
is modified.

## Reproduce

From the repository root, using Python 3.12.14 on Windows:

```sh
python tests/test_doctor_ghidra.py
```

The tests run the real doctor CLI with disposable directories, installation
marker files and distinct `application.version` values. These are explicitly
discovery-only fixtures, not a Ghidra installation. No launcher is executed or
mocked. The child environment isolates home discovery and excludes tools from
PATH; prerequisite readiness is not the assertion under test. The JSON's
`ghidra.started` and `captured_binaries_executed` remain false.

Baseline: three failing subcases across the three test methods: explicit-only
selection is missed, legacy selection wins incorrectly, and an invalid explicit
selection is silently replaced. Modified: all three test methods pass,
including legacy-only and automatic discovery compatibility controls.
`selection-test-output.txt` retains the before/after unittest diagnostics with
the local checkout prefix replaced by `<local-checkout>`.

## Validation limits

This is configuration discovery only. A valid marker file does not prove that
Ghidra, Java, REA analysis, decompilation or a reconstruction build works.
There are no binary addresses, function-boundary claims, normalization masks,
Rust implementation changes or native/differential execution in this fix.
Node #115 and visor retain separate identities and receive no comparison claim.

Repository-wide checks have host/setup limitations, recorded in the PR:
GnuPG is unavailable; the inferred reference contains Windows-reserved
`node/aux.rs`; native binutils/toolchains are incomplete; the catalogue uses
host-dependent reference-path strings. These are not repaired or counted as
passing by this change. Gates and generated progress tables remain unchanged.

Next step: run the same change through the repository's fully provisioned
Unix checks and, separately, a real configured REA/Ghidra provider smoke test.
