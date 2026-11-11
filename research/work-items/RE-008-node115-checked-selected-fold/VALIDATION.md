# Observed validation and limits

New reconstructed Rust was authored only after the four literal fixture JSONs and constructor policy were frozen. Expectations were manually derived from the full target disassembly, not calculated by the new Rust. The 29 concrete fixture functions contain 32 fold observations; 12 more functions check the explicitly chosen host refusal policy. The pre-existing smoke test retains its 14 TSV rows. An independent source review checked all 617 generated test lines against the frozen literals before compilation.

Direct Rust 1.95.0 host builds at opt-level 0 and 3 each passed all 42 tests. Nine separately compiled source mutations were rejected by their designated literal assertions: seam equality, segment duplicate choice, tree duplicate choice, wrapped carry, ignored carry, extra consumption, wrong child frontier, exhaustion cursor retention, and truncated 20-byte comparisons. These are mutations of independently authored Rust, not execution or emulation of captured machine instructions.

Two compile-only x86_64-unknown-linux-gnu rlib builds with opt-level=3, overflow-checks=on, codegen-units=1 and -D warnings produced identical 102890-byte archives, SHA256 7f5e0c3e6d627120a402d7d3bbb70e04cd84b66f7350d9f4a2c6c4295a567603. Neither archive was executed. This is own-build repeatability, not a binary comparison against node115.

The existing weighted-fold harness copies lib.rs into mutation folders. The new module declarations exposed a real missing-module compile failure (E0583), retained under validation/rust-controls-01/existing-harness-missing-modules. A single explicit two-module copy loop fixes that integration point. Only that exact copy-loop AST was evaluated in isolation; the surrounding instruction evaluator was never imported or run. Each of the three existing Rust mutations then compiled with -D warnings and was rejected by its original smoke test. This proves the relocated source closure, not the entire existing harness.

Two fresh GNU collections used the pinned target and complete three FDE extents. Both exited zero with empty stderr; all six native stdout/stderr files and semantic records matched exactly. Each control run passed 101/101, including 42 actual encoded-byte alterations checked below whole-file identity at named guards. Python normal and -O results are identical (SHA256 ce647b7da162e896b230705cb10e06c08e4c8f838574a724288a892de47924dd). These controls validate static bindings and collector behavior; they are not a semantic runtime oracle.

The validation directories retain commands, exits, raw streams or explicitly labelled path-only projections. PATH-PROJECTIONS.json identifies every altered receipt and its original and projected hashes. No compiler binary, captured target, test executable or private runtime dataset is committed. The selected static exports and literal fixtures are byte-exact.

## Reproduce the independent source tests

From the repository root, choose the pinned Rust 1.95.0 executable and fresh output paths:

    /pinned/rustc --edition=2021 --test src/node115-weighted-fastfold/lib.rs -C opt-level=0 -o /fresh/tests-debug
    /fresh/tests-debug --test-threads=1
    /pinned/rustc --edition=2021 --test src/node115-weighted-fastfold/lib.rs -C opt-level=3 -o /fresh/tests-optimized
    /fresh/tests-optimized --test-threads=1

For the static evidence, run the reviewed packet-local collect.py with --target artifacts/node/115/hl-node, --objdump /admitted/GNU/objdump and --output /fresh/collection. Run controls.py with the same --target, --evidence /fresh/collection and a fresh --output. Use isolated Python -I -B -S; repeat controls with -O. A second collect.py run may use --check /fresh/collection. These entrypoints never execute the captured target.

Full make test and the old weighted-fold evaluator were not run: their transitive closure includes captured-instruction evaluation outside the authorized static scope. Hosted CI and native runtime equivalence are not claimed. All acceptance gates remain false and no byte-coverage credit is added.

The first final diff check found one extra LF at the end of the generated test source. That failure is retained under validation/final-packet-check-01. Exactly that byte was removed; TEST-SOURCE-NORMALIZATION.json binds both hashes. All other test bytes and production source remained unchanged. Direct debug/optimized builds of the final public files, now also with -D warnings, again passed all 42 tests; validation/rust-final-source-01 retains those actual results.
