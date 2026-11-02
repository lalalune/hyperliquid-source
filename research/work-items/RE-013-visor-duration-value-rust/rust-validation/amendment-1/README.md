# Mutant-only compilation correction

The original source, tests, client, build.py, SOURCE-FREEZE.json and all61
pre-code files remain byte-identical. The initial authorized author run stopped
at command58: rustc rejected unnecessary parentheses in the deliberately wrong
implicit-leading-bit variant under -Dwarnings. This is a harness construction
failure, not a semantic mutant kill or production-source failure. The four
baseline streams had matched all59,159 expected values; only the first two
mutants had completed both profiles. The whole run did not pass.

The original rule deleted the OR term from u128::from((bits & mask) | leading),
leaving u128::from((bits & mask)). build-amended.py instead replaces the complete
expression with u128::from(bits & mask). Its deliberately wrong arithmetic is
unchanged; redundant parentheses are removed without weakening compiler flags.
The other19 generated mutant sources are byte-identical. Their expression/uses
were inspected for remaining obvious syntax/unused-name hazards; no unobserved
compilation result is claimed. Actual production code and independent expected
values are unchanged.

The only other harness changes admit SOURCE-FREEZE-2.json and explicitly verify
the original source freeze, five source files and six harness files. The unified
patch retains every change. A separate coordinator amendment/build gate is
required before the fresh run. Do not run or modify the historical original.

failed-initial contains the actual58-command raw stdout/stderr, outer streams,
post-source static receipt, partial outcomes and manifest. All16 produced
rlib/client artifact references have exact private byte archives;8 contain
private HOME path bytes. Public records retain their identities and clearly
exclude those binary payloads. No bytes are masked and no cosmetic rebuild is
performed. The original private run remains intact. Archive admission attempts
are recorded privately; they did not rerun or alter compiled artifacts.

The frozen original harness retains a timeout/launch-error receipt limitation:
if subprocess.run raises before producing a completed process, that inner
command has no receipt. It was not exercised by the initial compile exit101.
Any future occurrence must stop qualification and be reported; this narrow
amendment does not change that unrelated frozen mechanism.
