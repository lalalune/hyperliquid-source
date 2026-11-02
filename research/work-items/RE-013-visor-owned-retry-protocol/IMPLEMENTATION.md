# Visor duration and owned retry values

The extension to PR #1599 implements the frozen supplied-callback retry operation in `src/visor-retry-protocol`. It uses the unchanged sibling `visor-duration-value` from the same PR. Attempts, sleep replies and cleanup are caller-supplied callbacks; the library contains no direct process, clock, filesystem or network calls. Qualification supplies inert responses and observes real owned values.

Review the library and its 11 focused tests, then [SOURCE-PROOF.md](rust-validation/SOURCE-PROOF.md) and [PROOF.md](PROOF.md). The native core comprises four complete FDEs, 1,095 bytes and 291 instruction rows, under the stated memory, frame, ordinary-return and ownership premises. Six additional bodies provide dependency or caller context. The previous duration proof and implementation remain unchanged; none of its recovered bytes are counted again. All 336 entries of its public manifest and all 54 retry pre-code files retain their original bytes.

The operation preserves the first attempt before schedule selection, `None` versus an empty schedule, lazy conversion of reached delays, interrupted sleep remainders, error replacement and destruction order, terminal value identity, and optional cleanup. Invalid sleep replies have separately documented safe refusal policies. The frozen corpus contains 727 conditional native cases and 48 policy cases. The input-only observer uses actual weak references and distinct error, cleanup-error and terminal types.

## Observed qualification

The author and coordinator each completed 220 commands: 190 exit zero, 28 deliberate input/argument refusals with exit two, and two deliberate focused assertion failures with exit 101. In each profile, the 11 new tests and eight unchanged duration tests pass. Each run produces 56 complete streams of 775 results: six clean streams, 48 streams from 24 compiled mutants, and two from the separate option control. All 56 corresponding streams agree across the two runs. The 21 native mutants change native cases; the three policy mutants preserve every native case.

The frozen output protocol does not observe the attempt's option argument. A separate control changes option zero to one: its complete corpus output must remain equal, while the dedicated test must fail in both profiles. This is a focused assertion check, not a stream-detected mutant.

Both initial attempts remain recorded as failures. Their 17 child commands exited zero, including the debug tests and client link, but the harness then rejected two dependency rlibs before running any value client. [RTP002](rust-validation/BRIDGE-AMENDMENT.md) gives the exact correction: dependency tests use a separate target directory; two admission lines name the additive freeze. Production source, tests, client, expectations and original harness remain exact. The amended runs' isolated static replay matches the frozen pre-code report.

The coordinator rehashed 880 successful-run raw references and 336 private compiled-artifact references. Same-path clean repeats match all six library/dependency/client artifacts per run. Separate directories match none of those six, and the author/coordinator comparison matches none of 168 artifact pairs. No cause or cross-directory byte reproducibility is claimed. See [ROOT-COMPARISON.json](ROOT-COMPARISON.json) and [AUTHOR-QUALIFICATION.json](AUTHOR-QUALIFICATION.json).

## Inspect and reproduce

The four attempts' exact safe metadata and raw streams are stored in one standard [receipt archive](qualification/receipts.tar.gz). Its [index](qualification/BUNDLE-INDEX.json) maps each original command reference to a content-addressed archive member; [run summaries](qualification/RUN-SUMMARIES.json) separate the failed and successful attempts. It preserves 474 commands and 948 raw references. Original command JSON bytes are unchanged. Eight launcher JSON originals containing personal paths stay private with their original hashes and explicitly labelled metadata projections. No command stream is redacted; compiled payloads are private and represented by identities.

From this packet directory, the read-only helper verifies all member hashes and raw references without extracting files or executing archive content:

```sh
python3 qualification/inspect_bundle.py
python3 qualification/inspect_bundle.py --list
python3 qualification/inspect_bundle.py --show runs/author-amended/receipts/commands.json
```

The coordinator also compared every archived original to the actual four run directories independently of this helper. `tar -tzf qualification/receipts.tar.gz` provides a standard archive listing. The final public manifest authenticates the helper, index and archive; integrity checks do not prove the native theorem.

For a full host qualification, use the exact macOS arm64 Rust 1.94.1 payloads in `TOOLCHAIN-PINS.json`, the authenticated captured Visor as inert input, and fresh output/map paths. From the repository root:

```sh
python3 -B research/work-items/RE-013-visor-owned-retry-protocol/rust-validation/build-amended.py \
  --toolchain /absolute/path/to/1.94.1-aarch64-apple-darwin \
  --out /tmp/visor-retry-review \
  --private-map /tmp/visor-retry-review-paths.json \
  --source-freeze-sha 3050b0ce0bd8a5fe3966a453340b581cdcd5c2729cfb6b5d5662b764d7035048
```

The frozen source-absence guard is replayed through an exact isolated pre-code copy. Toolchain payloads and selected linker/SDK inputs are bound; the host OS, dyld and complete SDK are not hermetic. No captured execution or instruction evaluator, live command/sleep/network behavior, arbitrary unwind equivalence, original ABI/compiler identity, or component completion is established. The unchanged baseline's repository checks are context, not a full test-suite run on this extension or hosted CI evidence.
