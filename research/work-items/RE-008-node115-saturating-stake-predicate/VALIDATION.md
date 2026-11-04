# Validation record

This record separates authenticated static bytes, mathematical-reference
qualification and actual independently authored Rust execution. Final archive
and repository/publication review are separate. The target node was never
executed or emulated.

## Frozen identities and order

Target: node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `05bc2de303c05525b71e7e257426e741bc66a390`.

| Historical input | SHA-256 |
|---|---|
| Private native contract freeze | `7f2402818199ebcfe283e66b06a51af5d0eb062342c310591bd8f8f66c3eaecd` |
| Host contract | `4bb6a164423609b2310b7952351be5e88f8583d205b1ec144e9393cfde92a28e` |
| Forty manual cases freeze | `eec1e900dd60abb77deda2d5aaabcf54ee87fb1f1d790ea5013aedce77a4f40f` |
| Reference/generator source freeze | `08e1d02c3efb930a8f5717e072685682197c437a1db5f398941cb5ddd1690fad` |
| Eight-file corpus freeze | `e97921cc0b00648319b053a661860cd3dc7ba5f10626dc355a0b1bd6d4070133` |
| Initial five-file Rust source freeze | `4203e5cbe053b143b5c012926371bc1b3bdf8462869d447ad8b5e2e06b119fd7` |

The corpus freeze timestamp is 2026-11-04 06:50:04 UTC; the initial Rust source
freeze is 06:52:55 UTC. Original frozen records and earlier draft wording remain
unchanged. The source author had reviewed reference/manual material, so no blind
authorship is asserted. The independent source reviewer completed its review
after the parent had already reported the admitted builds; it is not described
as a pre-first-compilation gate.

| Actual compiled input | SHA-256 |
|---|---|
| Cargo.toml | `819ec89c303f8602098639a5017d692dacddb54e5147d6e0eb5da95589698e41` |
| Cargo.lock | `fb340ef4281412b379210c295146c66a4dae1269a653129fddc9cf996bb8e8d1` |
| src/lib.rs | `2bc380ec6b23c593aee66d3356e7157c956edb80bb94e72b9f183905c6133b89` |
| src/main.rs | `8e03f6de50b324f7c10ea6dfd6faf4e34715075b4d517580df7f3fd9cdefc285` |

## Actual completed results

The private static helper, SHA
`c315af78182596bf40218e674a06c48cfd9beba8b3372c1908ad38ce57498c76`,
passed 68 controls in normal and `-O` Python. Both results are identical, SHA
`16784de9efac6f747ccf2d63db38810487d66e80b860b051b87da952ea5bc037`.
The retained [result](validation/static-private-result.json) binds five complete
FDEs, 2,542 bytes, 643 instruction rows, 16 calls and 98 branches. Its guards
also bind the imports, failure relocation, source data and CIE/FDE records.
Counterfactual controls change in-memory bytes below only the universal identity
layers; passing means the intended structural check rejected them. No altered
native program was executed and these are not Rust semantic mutation results.

The parent comparator passed [90 synthetic controls](validation/comparator-result.json).
These distinguish process/format/identity/missing/extra errors from complete
well-formed value mismatches. They do not exercise the real driver or recompute
the predicate. B greater than S remains a well-formed result. The comparator
accepts the caller-recorded process exit; it does not itself launch or observe
the child.

The mathematical reference matched all [40 manual cases](reference/manual-qualification-01/result/RESULT.json),
with zero mismatches. Two actual generator runs used Python 3.14.3 with
`-I -B -S`; both exited zero with empty stderr and produced eight identical
files. There were 8,026 requests, 8,011 retained rows and 15 aliases. Retained
statuses are 7,971 ok, 33 bounds and seven order; the original forty input and
expected rows remain exact byte prefixes. The corpus is finite, conditional
value evidence, not a universal or independent native-runtime observation.

[Four builds](validation/build-result.json) passed with Rust 1.95.0: host debug,
host release, a fresh repeated release target, and Linux x86-64 `--lib`.
Linux output was not executed. The two host release executables share SHA
`088f8ce3358f15d715452609c25b0f4f52cd0a54d2d98228444fc091eb9df7f5`.
The debug executable SHA is
`527d0ad57f2af3eedd9360952e78fd2f33180d82e7ad41a37ab9a7bc68f24508`.
These builds are of the new one-package dependency-free component, not a
recovered original build graph or full-node build.

[Debug and release comparisons](validation/rust-comparison.json) each exited
zero, emitted 8,011 complete rows and matched all frozen expectations. Both
stdout streams have SHA
`a4786743d6a6e27a7ca516d9d1947a983244aeb61a221efed20031b443cac02a`,
153,450 bytes, and empty stderr. Input SHA is
`22b9f71275a5b6b00506b4b23b760ae8b5f47f66263c513c4421fe01cb9d7b44`,
5,494,944 bytes. Inputs enter only stdin; expected data stay with the parent.

Two earlier failed preparation commands are retained in the raw archive. The
initial metadata admission compared hydrated proposer disassembly with direct
`git show` output, which was an LFS pointer; it exited one. The correction bound
the committed pointer's oid and size to the hydrated bytes. Initial static
reconciliation also exited one on `KeyError: pc`: the peer schema named that
field `va`. An explicit `va`-to-`pc` mapping allowed the cross-check to proceed.
Neither correction changed native bytes, the semantic contract or expectations;
these are admission/schema failures, not native or Rust semantic failures.

## Semantic mutations and transport chronology

All twelve exact source faults built and executed successfully in both debug
and release. Each run returned 8,011 structurally valid rows with exit zero and
empty stderr before it was counted as a semantic detection. Its named manual
witness differed from the original expected row and matched the previously
declared prediction. Every host-refusal row remained unchanged. Definitions,
witnesses and raw patches are retained under [mutations/](mutations/); their
historical not-executed labels describe the earlier authoring stage.

| Variant | Intended fault | Differences per profile | Witness |
|---|---|---:|---|
| M01 | Replace wrapped seam equality with last equal | 520 | H18 |
| M02 | Select first ordinary equal key | 1,197 | H16 |
| M03 | Compare only nineteen key bytes | 5,334 | H38 |
| M04 | Deduplicate selected occurrences | 891 | H16 |
| M05 | Add a live weight on a miss | 4,152 | H12 |
| M06 | Ignore nonzero head for a contiguous view | 1,635 | H23 |
| M07 | Omit the second total span | 4,000 | H20 |
| M08 | Sum inactive physical rows | 4,468 | H08 |
| M09 | Wrap selected accumulation | 220 | H26 |
| M10 | Wrap total accumulation | 316 | H25 |
| M11 | Make the final comparison inclusive | 409 | H29 |
| M12 | Truncate final products to u64 | 316 | H33 |

The original transport qualification passed 119 of 121 cases, including exact
16,777,216-byte and 8,192-record inputs, their one-over refusals, element limits,
late malformed rows and ID preservation. Both advertised I/O probes instead
returned exit zero with empty captured streams. Their wrong-access-mode file
descriptors did not induce the intended errors. Tagged Rust 1.95.0 stdio source
explains why EBADF can become an empty successful read or a successful write;
the original runs did not directly measure errno.

The failed 119/121 result remains intact. Only two corrected controls were then
run, without changing source or rerunning the 119 successes. Directory stdin
returned exit two with observed empty stdout; a no-reader pipe on stdout
returned exit one with a diagnostic. The latter stdout was deliberately
uncaptured and has null byte/hash observations, not an observed empty stream.
These controls do not qualify failures after partial I/O progress, OOM, Linux
runtime behavior or native effects. Predicted OS errors and observed process
outcomes remain separate.

## Public reproduction and portability

The native public freeze is a distinct twelve-entry path projection, SHA
`3ded1e5f428bc795fe602bda98a7aab621582d51ad7fe904792130502f1d49b9`.
Its projected binding receipt SHA is
`b2141ffdf32eec2e59dbfc7094f3f1236f77a11f3f2ce278f388b746655bee94`.
Only those two pin constants change in the public verifier, SHA
`80c11211b2198881a2516205ce1882561514591ab57912fe3a25c09ece1f3e23`.
After separate source review, that exact public verifier passed all 68 controls
on 2026-11-04 at 07:08:58 UTC with exit zero and empty stderr. Its result equals
the private result after excluding only the declared verifier/freeze/bindings
identity fields. This is a separate actual run, not a relabelled private result.

The public reproducer, SHA
`f871fea4cb10c755f5a76d8fc944f2a1273213cff49cd815b1e7c7e153cf6774`,
subsequently completed its first baseline-plus-mutations run at 07:22:06 UTC:
41 commands, thirteen release builds and thirteen complete 8,011-row driver
outputs. The baseline matched exactly; all twelve variants reproduced the
table's counts and named witnesses. The helper does not regenerate the corpus
or repeat the static, comparator-control, transport, debug or Linux checks.

A separate read-only output audit rehashed 82 child stdout/stderr references,
two outer-launch streams, 65 copied source-file observations, thirteen binaries
and the actual tool identities. Its independent grammar/row comparison confirmed
every complete stream is byte-identical to the corresponding original private
release output. It imported no comparator or model and reran no executable.
The audit author also authored the public runner; this is a separate recount of
root-executed results, not blind runner authorship or another native lineage.

Exactly three native files contain declared absolute-prefix replacements:
one GNU file-name header, source paths in native-bindings, and the historical
binder command receipt. Their masks and both hashes are recorded in
[native/PORTABILITY.json](native/PORTABILITY.json). Instruction rows, opcodes,
FDE/CIE/data/relocation bytes, the contract and the proof are unchanged.
The historical `native_texts` hashes and `binding.stdout` receipt hash continue
to identify original bytes. The standalone historical binder also retains its
prior-admission dependency; the public reproduction entrypoint is the static
verifier, not an assertion that the old scout tree is bundled here.

[corpus/STORAGE.json](corpus/STORAGE.json) declares the three deterministic gzip
containers. Decompressed content matches the original raw hashes. The original
corpus freeze and summary are logical uncompressed inventories; they are not
invented manifests of the compressed public filenames. Reference, manual,
generator and comparator sources were copied byte-for-byte. Historical
admission-pending text in their plans is preserved provenance, superseded only
by explicitly recorded later actual results.

The [complete public raw command archive](validation/ARCHIVE.md) now contains
1,073 retained files; two fresh assemblies were identical and every stored blob
and original reconstruction passed separate read-only audit. Final repository
checks are recorded separately. The initial W20 doctor/verify baseline passed, but is
not final changed-tree validation. Full `make test`, hosted CI, container success
and all 92 full-scope acceptance gates remain unclaimed. Static and source
reviewers are additional checks on one capture lineage, not independent target
executions. No aligned compiled-byte window or new native-byte coverage is
registered by these finite qualifications.

## Final repository checks

`make doctor`, `make verify`, `make catalogue-check`, `make reproduce`,
Rust formatting and the staged whitespace check passed. The
[retained command/stream records](validation/REPOSITORY-CHECKS.json) include the
initial doctor failure: the restricted PATH selected Apple objdump and omitted
readelf. Prepending the already installed GNU binutils directory corrected that
environment issue without changing code or installing tools. Exact-path Git
attributes also preserve frozen comparator/manual EOF blanks and mutation patch
context after the initial whitespace finding. No frozen byte was trimmed.

Verification authenticated 32 imports, the unchanged source pins and 559 packet
manifests / 7,231 entries at that check. This command-record file was added
afterward; the final manifest is checked again separately. Catalogue generation
records 35 implementation areas, 20 Cargo manifests and 561 work-item directories.
Base already contained 560 directories although its displayed count was 559;
this contribution adds one directory. All 92 acceptance gates remain false.
Full `make test` and hosted CI were not run because the broad suite includes
captured-instruction evaluators outside the static-only boundary.
