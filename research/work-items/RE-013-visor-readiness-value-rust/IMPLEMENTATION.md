# Qualified host value reconstruction

The additive source phase now supplies a real dependency-free [`visor-readiness-value`](../../../src/visor-readiness-value) Cargo component for the sample-to-calendar-to-fixed60 relation. Its private canonical `Timestamp` API accepts supplied numeric values, exposes logical raw words, adds a saturating 60-second deadline and makes the strict local comparison. It performs no clock, filesystem, process or network operation. This extends the same #1361 contribution; it adds no byte-identity or whole-component gate credit.

The original pre-code phase remains unchanged. Its proof closes the four-body sample/current-date dependency and credits the earlier fixed60 helper/caller argument. Native scope is eight complete FDE bodies, 3,866 bytes / 910 rows, with selected-path success premises rather than generic behavior. The original source timestamp's lifecycle producer, imported failure, arbitrary/extended raw date/time words and later readiness behavior remain outside scope. Safe `None` is newly chosen refusal policy, not a reconstructed native error ABI.

The original 35-file pre-code freeze is `4c6243e6b61e350f73ca05095e142d5c3512de6f7d5078da9022f47dae40ee45`. Root pre-code authorization was `e646775e9036fedad9b3fdaca170d3be62855cdbf9b5938f6adc8a3a3b10c507`. Source/client/build freeze `e513c9fef9045e46c56d11fa1eeaa259cacbd64cf5c85405fa1869e163090f36` preceded compilation; the separate root source/build gate was `dbee21dda443c181a596a0134156531f4bcea5e8ff81ccf1ff4b8e7458863f1c`. No frozen file was edited after either phase. The old calendar packet is untouched.

The author actually ran the frozen harness to exit 0 with 178 retained subcommands:163 exited 0 and 15 malformed-input controls exited 2 as required. There were no failed compilation, source-test or valid-input runs. Results are in [`rust-validation/author/results.json`](rust-validation/author/results.json); complete commands/stdin identities/stdout/stderr are in `author/commands.json` and 96 content-addressed gzip streams. All 356 raw stream references were independently decoded/rehashed, all 48 full value streams re-compared, and the copied 101-file author archive was checked byte-identical to the actual output. [`AUTHOR-RESULT-AUDIT.json`](rust-validation/AUTHOR-RESULT-AUDIT.json) records that reading without rerunning the candidate.

| Actual qualification | Result |
| --- | --- |
| Original static replay during build |32 controls; 44 exact regenerated outputs |
| Debug/release source tests |8 passed per profile |
| Frozen 60,009 cases, debug/release in two clean directories |0 mismatching rows in all 4 streams |
|22 compiled semantic mutants, both profiles |All 44 own value streams differed from unchanged expectations |
| Exact-output comparator corruptions |All 10 rejected |
| Malformed input client controls |All 15 exited 2 with zero partial stdout |
| Empty valid input |Exited 0 with zero stdout |
| Offline/locked actual Cargo graph |One local package, library/test targets, zero dependencies |
| Own clean-directory artifact comparison |Both-profile rlibs and release client raw-equal; debug client unequal |

The corpus was fixed before source and uses whole Gregorian day counts/binary-search inversion and whole-nanosecond addition/clamping. The candidate uses bounded 400-year cycle subtraction and fieldwise second/day/year carries. Input-only Rust reads no expected outputs or semantic labels; the Python harness alone performs comparison. Mutants compile and emit their own full 60,009 rows; compiler errors, process failures or pass markers are not counted as semantic detections.

All commands preserve raw outputs. No value or artifact normalization/mask is applied. Debug client inequality is a known host-build limit; its cause has not been established. This is value agreement under the conditional native proof, not original compiler/type/ABI/machine-code equivalence or a complete/hermetic target build.

Rust/Cargo 1.94.1 and 97 installed bin/lib payloads are pinned and rehashed before/after. The run admits the genuine offline lock, exact five source files, no source symlinks/build hooks, fresh Cargo home, cleared build environment, explicit linker/SDK and lexical/canonical ancestor Cargo configs/manifests. Actual Cargo metadata's workspace root must equal the copied component. Selected linker/SDK files are retained by identity; the complete host OS/dyld/SDK is not a hermetic input claim. Runtime caches and build products do not enter publication manifests.

To replay the unchanged static phase after source exists, use the original `verify.py` command without `--require-source-absent`. To reproduce the actual authored builds with the admitted installed toolchain, after reading the frozen harness, choose fresh output and private-map paths:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-013-visor-readiness-value-rust/rust-validation/build.py \
  --toolchain "$READINESS_TOOLCHAIN" \
  --out /tmp/hl-readiness-value-replay \
  --private-map "$READINESS_PRIVATE_MAP" \
  --source-freeze-sha e513c9fef9045e46c56d11fa1eeaa259cacbd64cf5c85405fa1869e163090f36
```

`READINESS_TOOLCHAIN` is the existing admitted 1.94.1 host payload; `READINESS_PRIVATE_MAP` must be a fresh file outside this public packet. The actual author run used logical `<BUILD>` for its fresh canonical `/private/tmp` root; its private mapping/admission is retained in session artifacts. Public commands contain those explicit logical substitutions, while raw stdout/stderr bytes remain untouched. No captured executable or instruction evaluator is run by either phase.
