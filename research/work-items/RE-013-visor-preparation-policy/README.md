# RE-013: Visor directory preparation request/error policy

Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, component `visor`.
Target captured Visor: 8,305,392 bytes, SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

The conditional prepared-path and initialized-prefix packets (#1375/#1402)
leave preparation helper results opaque. This packet qualifies the selected
recursive request/error policy: first-phase classification zero walks upward;
classification 12 accepts an existing metadata predicate; saved slices are
requested in reverse order afterward. In replay, classification zero is an
error rather than a fresh upward search. Normal zero return alone proves
neither new directory creation nor even an actual mkdir request.

[PROOF.md](PROOF.md) gives addressed branches, table coordinates, data/call
bindings, the long-request callback and exact scope/premises. It is a normal
request protocol over the actual supplied slices. Full parent-path grammar,
filesystem effects, helper/lifetime/concurrency contracts, original Rust
types and whole-component equivalence are not claimed.

## Reproduce statically

Author platform: Linux x86-64, Python 3.12.3, GNU objdump/readelf 2.42,
LLVM objdump 18.1.3. With P set to this packet directory, from repository root:

```sh
B=artifacts/visor/captured/hl-visor
python3 -B "$P/survey.py" --binary "$B" --output work/visor-preparation-new
diff -r "$P/observed" work/visor-preparation-new
python3 -B "$P/verify.py" --binary "$B" --receipt work/preparation-integrity.json
python3 -B -O "$P/verify.py" --binary "$B" --receipt work/preparation-integrity-opt.json
python3 -B "$P/check_policy.py" --binary "$B" --receipt work/preparation-policy.json
python3 -B -O "$P/check_policy.py" --binary "$B" --receipt work/preparation-policy-opt.json
python3 -B "$P/crosscheck_llvm.py" --binary "$B" --output work/preparation-llvm-new
diff -r "$P/independent" work/preparation-llvm-new
make doctor
make verify
make catalogue-check
make reproduce
```

Use fresh output/receipt locations. The full target identity is required before
parsing/native disassembly; the native tool receives an owned 0400 snapshot,
whose bytes and every decoded row are checked. Complete raw FDE/CIE records,
RELA/data/direct-call bindings and native outputs are retained.
VALIDATION.json contains actual results, counts, source/log hashes and limits.

The abstract policy checker uses supplied slice identifiers and mathematical
branch tables, not a captured-CPU evaluator, target iterator emulator or host
path library. None of the captured target's callbacks, bound filesystem/errno
operations or network actions is invoked. Full root `make test` is NOT RUN because unrestricted
discovery includes captured instruction evaluators outside this session's
static-only authorization. Hosted CI/full build/container success is NOT
CLAIMED; the submission remains a draft with `[skip ci]`.

## Attribution, overlap and progress

New code/prose are independently authored under this repository's MIT terms.
The collector/verifier/native comparison adapt this author's MIT draft1375
packet at frozen head `0e740791da481f38d368525e75e92886842024f3`.
The first-NUL result and borrow lemma are credited to the accepted
`RE-013-visor-shell-nul-admission` packet (#1351); they are reused premises,
not another scan contribution or a claim of rerunning its original recipe.
Full converter/finalizer context is retained with current provider outputs.
Original capture rights remain unchanged. No unlicensed inferred can1357
source was read or copied for this outcome.

Live main/open-PR ownership was checked before selection and must be rechecked
before submission. This differs from #1361 calendar arithmetic, #1375 payload
selection, #1394 metadata/download/publication flags and #1402 initialized G.
Changes are confined to this packet; imports, source pins, generated catalogues,
progress and all component gates remain unchanged. Retained raw byte/row totals
are evidence scope, not function-recovery or matched-window completion credit.
