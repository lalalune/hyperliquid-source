# RE-013: Visor configuration-byte request protocol

Conditional static research for Visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`, base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. See PROOF.md for addressed premises and limits.

The primary request combines G1 with `/code/static_config`. Its returned marker or returned parser error selects byte0x21. Selected field fallback instead reacquires H2/G2 and requests G2 with `/aws_name`; its own marker or conversion0x4f reaches diagnostic calls and UD2 if those calls return. These fresh observations must remain distinct. The trim leaf returns the maximal middle UTF-8 slice for its addressed25-code-point predicate; empty/all-whitespace input returns the original pointer and length0. Full parser grammar, conversion map and runtime file outcomes remain unknown.

From this directory, with an authenticated non-executable capture at `$BINARY`:

```sh
python3 -B survey.py --binary "$BINARY" --output observed
python3 -B verify.py --binary "$BINARY" --receipt integrity-normal.json
python3 -B check_bindings.py --binary "$BINARY" --receipt bindings-normal.json
python3 -B check_language.py
python3 -B crosscheck_llvm.py --binary "$BINARY" --output independent
```

Outputs are create-only; preserve retained files and use fresh output paths when reproducing. The verifier regenerates in private temporary directories and compares the committed observed records. Repeat with `python3 -O -B`; VALIDATION.json records actual commands and normal/optimized receipt equality. GNU binutils2.42 and LLVM18.1.3 native byte partitions are compared without masks. Pure abstract branch/scalar/offset checks support the manual proof and are not a CPU or target comparator.

Root `make doctor`, `make verify`, `make catalogue-check` and `make reproduce` results are recorded. Full `make test` is NOT RUN because flat discovery includes captured-instruction evaluators outside the authorized static workflow. This is a draft with skip-CI title; no hosted CI, target execution, full Rust build, component-gate completion or recovered-byte credit is claimed. Preserve unknowns even when controls pass.

New source/docs are independently authored under the repository MIT license; target evidence retains upstream rights. No unlicensed inferred source was copied.
