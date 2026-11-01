# Current-base integration addendum

The new branch starts from current main
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The original source preservation
commit `01723660c6b76e5e3cb69a2d49ff89454b40a080`, measured `build-c1/` files,
independent reviews and frozen proof remain unchanged. They are historical
observations at their recorded source/provider/target identities, not new
current-base builds. The original frozen proof's statement that #1334 was
open is retained as historical provenance; #1334 is now merged.

`ownership.json` records all 58 open PRs and 100 recent closed PRs at the
resume intake, plus current source searches and the explicit scope of merged
#339/#1334. Neither recovers this complete constructed state/write-mask and
Unicode-scalar relation. The shared decoder gap left by open #1384 belongs to
a higher consumer. This contribution adds no duplicate outer ASCII address API.
The audit cannot rule out undeclared work, so live scope is rechecked before
submission.

Only the main runner's `BASE` absence-control pin changes from the original
base to the current base. Production Rust, input-only client, external tests,
Python controls and pre-source authority stay byte-identical. The retained
own Rust clients/libraries are hash-bound to the original actual compilation;
they are not durable dependencies or captured target binaries.

`replay_retained.py` performs a bounded current readmission: reauthenticate the
full target and both spans, all 103 installed provider payloads/manifests,
retained own-library/client identities and original source correspondence;
then invoke both actual own clients with frozen raw input only and compare
all 185,490 complete observations over 39,850 cases per profile. It also runs
the three focused Python corruption/regeneration controls. New raw streams,
exact commands and before/after identities go to a new owned output directory.
The full compiler experiment remains reproducible with the main runner.

```sh
python3 -B research/work-items/RE-001-hex-pair-iterator-94/resume/replay_retained.py \
  --build /tmp/hl-resume-20261101/hex-iterator-build-c1 \
  --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc \
  --output /tmp/fresh-hex-current-replay
```

Current-base checkpoint `ba9cb94bad8617cd1f8cd5565306ae37f6861f81` passed the
actual readmission/replay: both profiles matched all 185,490 observations over
39,850 cases and the three focused Python controls passed. `replay/` retains
the four command records/eight raw streams and unchanged before/after
source/provider/target/artifact identities. The historical C1 compiler and
mutant results remain historical; this current run performs zero compiles.

The four current static checks (`doctor`, `verify`, `catalogue-check`,
`reproduce`) all exited zero on that checkpoint. `static/` retains exact
commands, eight raw streams and 10,930 physical tracked-file records plus
seven actual clean pins unchanged before/after. `base-static/` retains the
same four checks on the current clean base (10,814 physical records).
BEFORE/AFTER maps use lossless gzip containers; the source/stream bytes are
unchanged. `static_runner.py` is the actual root-supplied inventory/check
recipe with only the owned view/output/expected-head constants changed.
The two current peer receipts independently verify these actual records
without a second run. Final packaging changes only evidence/documentation.

No new compiler run, target execution, instruction evaluator, full-suite,
hosted CI, original ABI, rebuilt target-byte equality or component-gate claim is made.
Full current `make test` and CI stay NOT_RUN: expanded evaluator families are
not authorized. Publication commits use `[skip ci]`.
