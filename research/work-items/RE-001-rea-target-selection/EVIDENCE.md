# RE-001: reject ambiguous REA target commands

- Component: shared static-analysis tooling supporting the function-map workflow.
- Bounded question: can surplus arguments silently change the selected artifact?
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: `can1357/hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`,
  unchanged and not used as implementation source.
- Claim status: observed CLI defect and observed correction; no native-node
  semantics, reconstruction, equivalence, or component gate is claimed.
- Changed code: `tools/rea.py`; regression: `tests/test_rea_launcher.py`.

Each artifact is checked separately against `provenance/artifacts.json`:

| Target | SHA-256 |
| --- | --- |
| Node #94 | `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` |
| Node #115 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| Captured visor | `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31` |

## Reproduce

Run from the repository root with pinned submodules and LFS inputs materialized:

```sh
python3 tools/rea.py target 115 --format json
python3 tools/rea.py target 115
python3 -m unittest discover -s tests -p test_rea_launcher.py -v
make doctor verify catalogue-check
PATH="/opt/homebrew/opt/binutils/bin:$PATH" make test
git diff --check
```

The PATH prefix selects the installed GNU tools for the existing suite on macOS;
no shell configuration was changed. Environment: macOS 26.7.1 arm64, Python
3.14.7, Git 2.50.1, Git LFS 3.8.1, GnuPG 2.2.41, GNU objdump
2.47.20260726. Rust 1.94.1 and 1.95.0 are installed for the repository preflight.
The target subcommand requires neither the REA npm package nor a Node runtime
or Ghidra. All CLI controls invoke the real Python launcher and hash the actual
captured files; the captured executables themselves are never launched.

Setup initially left the reference submodule's LFS pointer unmaterialized.
`git -C references/can1357-hl lfs install --local` followed by
`git -C references/can1357-hl lfs pull` restored the pinned bytes. No setup code
or artifact pin is changed by this contribution.

## Evidence

On the base revision, `target 115 --format json` exits successfully with the
path and digest of node #94. `target visor extra` and `target unknown extra`
also select #94. The branch in `main()` reads the requested name only when the
entire argument list has length two; every other length uses the default.
Thus an unsupported option or a second target can produce a usable but wrong
analysis target instead of an error.

`cli-comparison.json` retains stdout, stderr and exit status for the same seven
commands before and after the fix, plus the measured identities of all three
artifacts. Only the absolute checkout prefix is normalized to `<repo>`.
The four valid controls (default, #94, #115, visor) are byte-identical; the three
malformed commands change from exit 0 / node #94 JSON to exit 1 / empty stdout
and a usage diagnostic. There is no instruction-address or function-boundary
claim: the coordinates here are whole-file artifact paths and digests.

## Implementation and comparison

Reject argument lists longer than `target` plus one name before looking up or
reading an artifact. This preserves the existing default and explicit-target
behavior without extending this local subcommand to accept REA package flags.
It also preserves the existing artifact size/hash check and unknown-name check.

Two added tests exercise actual subprocesses. One checks four valid selections
against the pinned artifact manifest. The other checks five malformed forms:
an unsupported option after #115, an extra token after visor, two release names,
an unknown name plus an extra token, and an option without a target. Each must
exit 1, print no target JSON, and produce a usage message without a traceback.

The base with these tests runs 433 tests and reports exactly five failures,
all from the malformed-argument regression subtests. The existing tests and
all four valid selections pass. The focused suite after the fix passes all
seven tests. See `validation.txt` for the full post-change result and checks.

## Results and limitations

No Rust implementation, machine-code comparison, native-provider analysis,
captured binary execution, or hosted CI result is claimed. `make reproduce`
does not apply: no literal analysis, inventory, or interpretation of captured
code changes. Progress and generated catalogues remain untouched. No gate is
requested.

The doctor reports static analysis ready and exact rebuild unavailable. Ghidra
is absent and the optional LLVM objdump probe times out; GNU binutils supplies
the full suite's disassembly cross-checks. These limits do not affect the
target subcommand exercised here. A next independent question is whether the
native-provider handoff retains the selected artifact identity and coordinate
system; this patch does not test or alter that handoff.
