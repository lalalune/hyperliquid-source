# RE-013: prepared shell-output path selection

Question: how does the preparation helper produce the opaque T used by the
accepted shell/formatter packets (#1266/#1345), and which constructed object
does it return on each normal branch?

Target: captured Visor SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
8,305,392 bytes. Analysis base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
All addresses are ELF VAs, independently mapped through file-backed PT_LOADs.

Under the explicit storage, callback and allocation premises in PROOF.md,
P = G || `/tmp/` || X and Q = `/tmp/` || P. Here G is an initialized global
payload whose actual value is unproved, and X is the caller's input slice.
The helper chooses Q only after the first predicate is zero and its preparation
call returns nonzero, followed by a nonzero second predicate or a zero second
preparation result. Both preparation calls returning nonzero with zero predicates
selects P. A separate caller check can still return early before the command
formatter. None of these labels establishes a filesystem helper's semantics.

The new addressed bodies are the 915-byte preparer, 210-byte later check, and
20/19-byte string/slice callbacks. Seven retained formatter/caller/sink bodies
are reused context, not additional function or byte-recovery credit. No compiler
build, source Rust type, component gate or whole-target equivalence is claimed.

## Reproduce without executing the capture

Use Python 3, GNU readelf/objdump 2.42 and LLVM llvm-objdump 18.1.3.
The scripts authenticate the entire input before exporting and refuse existing
output paths. They create private 0400 snapshots for native parsers. No target
instruction evaluator, emulator, dynamic loader or captured command is invoked.

```sh
python3 survey.py --binary /absolute/nonexecutable/visor.elf --output /tmp/new-path-observed
python3 verify.py --binary /absolute/nonexecutable/visor.elf --receipt /tmp/new-path-normal.json
python3 -O verify.py --binary /absolute/nonexecutable/visor.elf --receipt /tmp/new-path-optimized.json
python3 crosscheck_llvm.py --binary /absolute/nonexecutable/visor.elf --output /tmp/new-path-llvm
python3 check_argument.py --binary /absolute/nonexecutable/visor.elf --receipt /tmp/new-path-argument.json
python3 -O check_argument.py --binary /absolute/nonexecutable/visor.elf --receipt /tmp/new-path-argument-opt.json
```

`verify.py` performs two complete native regenerations per invocation and eleven
capture/record/output-preservation controls. `check_argument.py` binds the cited
instructions/data, checks three byte fixtures and the sixteen-row abstract
choice table, provides three abstract mutant witnesses and rejects eight
below-image-hash binding mutations. These controls have separate meanings:
record integrity and boolean consistency do not independently prove the manual
native-to-formula argument or its opaque premises.

Actual receipts, provider versions, exact source hashes and root-check results
are recorded in VALIDATION.json after qualification. No unrestricted `make test`
or hosted CI success is claimed: full discovery includes captured-instruction
evaluators outside this static-only authorization. Root doctor/verify and relevant
catalogue/reproduction checks are recorded separately.

## Remaining work and attribution

Global initialization, detailed path-component/conversion and filesystem helper
contracts, error/cleanup callbacks, allocator prefix preservation, actual file
effects, execution and complete component acceptance remain open. Read PROOF.md
before using the conditional result. No current input, private runtime data,
unlicensed inferred Rust source, external repository code or paid dataset was used.

The collector, regeneration verifier and LLVM comparator adapt this contributor's
MIT scripts from accepted #1345. Formatter/sink evidence is explicitly reused;
imported capture exports keep upstream rights. New scripts and explanation are
independently authored under the repository MIT terms. No imported input, pin,
generated progress file, shared tool or acceptance gate is changed.
