# RE-013: selected-caller Visor parent slices

Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; separate Visor capture
SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
8,305,392 bytes. Addresses are linked ELF virtual addresses before load bias.

The prepared-path result in draft1375 and preparation policy in draft1437 leave
the actual temporary predicate/preparation slice opaque. This packet supplies
an addressed conditional proof for the caller's concrete initialized iterator
state. It removes one semantic final component, trims trailing empty/dot
components of the remainder, preserves interior bytes and dot-dot components,
and distinguishes root/no-component bypass from an eligible empty parent.
The later UTF-8 validator can retain the original full candidate on failure.
The returning P/Q allocation remains distinct and is not truncated.

Examples of the conditional result, not target executions:

| Original bytes | Temporary selected bytes |
| --- | --- |
| `foo` | empty |
| `./foo` | `.` |
| `/a/./b` | `/a` |
| `a//b/c` | `a//b` |
| `a/../b` | `a/..` |
| `/./` | `/./` (root-only bypass) |
| `80 2f 61` (hex) | original bytes (invalid retained parent) |
| `61 2f 80` (hex) | `61` (invalid removed final component) |

The theorem has explicit immutable/nonaliasing storage, stack/call, normal
helper and length premises in `PROOF.md`. It covers this selected initialization,
not all private iterator states, Rust types, allocator/concurrency guarantees,
actual runtime G/X values or filesystem effects.

## Evidence and reuse

Five complete FDE extents retain 3,348 bytes / 873 GNU instruction rows:
caller `3a1780..3a1b13`, back-component `694cf0..695101`, remaining-slice
`678fa0..6791f6`, suffix leaf `678e70..678f93`, and credited UTF-8 context
`49b560..49b757`. GNU2.42 and LLVM18.1.3 raw address/byte partitions agree
without masks; the records include FDE/CIE,12 selected RELA and12 direct calls.
These ranges are prior retained context: zero new recovered-byte/function credit.

The new outcome is the selected-caller parent-slice relation and its composition
with the admission/bypass branches. Reuse the strict UTF-8 proof at pinned base
`research/work-items/RE-013-visor-child-args-utf8/PROOF.md`, including its full
storage/frame/nonwrapping domain. Its validator accepts embedded NUL at this
stage. That accepted proof is credited, not resubmitted or claimed rerun.

The separate prepared-path and preparation-policy context is frozen at public
heads `0e740791da481f38d368525e75e92886842024f3` (draft1375) and
`a486efada6ef6e533d2f047be81591226daf82ea` (draft1437). Native capture bytes
and relocations, rather than inferred reference source, ground this proof.
Collectors share this author's MIT static utilities from1437; new proof and
code are MIT. Imported capture rights remain unchanged. No can1357 source is
copied or relabeled.

## Reproduce without running the capture

Materialize pinned inputs under repository instructions first. Use Python3.12.3,
GNU objdump/readelf2.42 and LLVM18.1.3. From this packet directory, set B to
the repository's nonexecutable admitted Visor artifact path. Outputs below
must be new; existing evidence is deliberately preserved.

```sh
B=../../../artifacts/visor/captured/hl-visor
# From research/work-items/<packet>, the repository root is ../../..
python3 -B survey.py --binary "$B" --output /tmp/visor-parent-fresh
python3 -B verify.py --binary "$B" --receipt /tmp/visor-parent-integrity.json
python3 -O -B verify.py --binary "$B" --receipt /tmp/visor-parent-integrity-opt.json
cmp /tmp/visor-parent-integrity.json /tmp/visor-parent-integrity-opt.json
python3 -B crosscheck_llvm.py --binary "$B" --output /tmp/visor-parent-llvm
python3 -B check_language.py
python3 -O -B check_language.py
python3 -B check_bindings.py --binary "$B" --receipt /tmp/visor-parent-bindings.json
python3 -O -B check_bindings.py --binary "$B" --receipt /tmp/visor-parent-bindings-opt.json
cmp /tmp/visor-parent-bindings.json /tmp/visor-parent-bindings-opt.json
```

Retained integrity receipts regenerate all records twice and reject10 controls
per normal/optimized mode. Binding receipts freeze873 native rows as an
identity inventory and reject17 addressed instruction-byte and3 RELA-addend
mutations after deliberately bypassing whole-image admission. This is binding
support, not873 semantic proofs or execution of mutated captured code.

The two independently formulated high-level byte-language specifications agree
over31 explicit fixtures and137,257 finite byte inputs (seven-byte alphabet,
length0..6), including23,376 valid-UTF8 prefix instances. Seven concrete
witnesses reject false simplifications such as normalizing interior slashes,
cancelling dot-dot or rejecting an eligible empty parent. They are abstract
specifications, not a CPU/instruction model or target behavioral comparator;
the addressed manual proof is essential.

Root `make doctor`, `make verify`, `make catalogue-check` and `make reproduce`
results and source hashes are recorded in `VALIDATION.json`. Full `make test`
is NOT RUN: flat discovery includes captured-instruction evaluators outside
the authorized static-only scope. Hosted CI, container/full Rust builds,
captured execution/emulation, target networking and component gates are not
claimed. The draft PR and commit use `[skip ci]`. Existing gate records and
pinned imports are unchanged.
