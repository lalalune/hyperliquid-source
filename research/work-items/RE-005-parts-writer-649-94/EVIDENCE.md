# RE-005: the 649-byte formatted-parts writer

- Component: serialization, node #94 formatting leaf.
- Target: Linux x86-64 node #94, SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Admitted base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Complete native primary: VA `0x1572b20..0x1572da9`, 649 bytes, 169 contiguous instructions, body SHA256 `8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3`.
- Claim: normal byte-request/effect relation under immutable valid inputs and supplied normal callbacks. No full component gate is requested.

The observed raw descriptor and 24-byte parts select prefix, full-u64 zero runs, u16 decimal numerals or raw byte slices. The reconstruction resolves the complete sequence, method-cache lifetime, lazy field/view reachability, persistent callback effects and canonical return byte. It has no fixed helper edge or formatter-header mutation. The separate outer 602 routine, its padding/header semantics, original pointer/ABI identity and real renderer behavior are excluded.

`independent-pre-source/PROOF.md` covers every native path. The final v2 authority was sealed before the new Rust: 69,359 distinct eleven-field inputs, 90,453 callbacks, 73,214 exact adjacent-event RLE records and all 65,536 u16 numeral payloads. `FREEZE.json` binds the independent plans, raw inputs and canonical outputs. `PROTOCOL-AUDIT.json` separately decodes the raw fields and processes every individual callback; RLE changes observation transport only. The production client receives only `inputs.tsv`.

The source contract and qualified domain are in `src/node94-parts-writer/README.md`. Inputs, record storage and byte views are immutable and valid when actually visited; callback methods are live Cells and observer state is a separate chosen borrowed object. Zero-request cases need no method/view binding. Requested raw empty slices remain requests. Extremely large u64 zero runs are not capped; finite tests use early failure for otherwise impractical traces, and the decreasing-remainder proof covers theoretical successful runs.

The genuine analogous official libcore candidate is 581 bytes against 649 target bytes. The measured static producer retains that extent mismatch and refuses a positive comparison. No cropping, stitching, normalization mask or compiled-window credit is claimed, so `research/byte-windows.json` is unchanged. Authored semantic Rust is not byte-equivalent to the captured function or original compiler.

## Actual implementation and comparison

The independently authored library is `src/node94-parts-writer/lib.rs`; the raw-only client and three meaningful units are adjacent. It is a real no_std/core library linked to the actual official std provider for tests/client, with no invented workspace, copied payload or stub dependency. Decimal request bytes come from its own quotient/remainder loop.

The complete corrected experiment ran at clean committed `51c0ea7fc4a035b4c0dd690f9310657b39ea9db4`. Actual O0, O3 and one additional O3 recipe each emitted all 69,359 canonical rows byte-exactly: 90,453 individual callbacks and 73,214 exact adjacent RLE records per client run. Three units passed in each O0/O3 profile, including full frozen raw transcripts, true zero-request laziness and borrowed-object identity with cached zero methods/live next-part methods/error stopping. Optimized rlib and client bytes reproduced exactly in the additional build. There is no native/own-Rust byte-equality claim.

Twelve separately recompiled source controls were rejected by complete output comparisons: raw tags treated as numerals 1,521 rows; number truncated to u8 65,656; wrong number field 66,194; wrong decimal digit 66,195; zero-run method reloaded 813; wrong zero literal 2,350; extra empty tail 29; ignored raw view length 1,790; noncanonical error status 2,815; changed fixed data 69,351; changed fixed table 69,351; changed method identity 69,351. `actual/RESULT.json` retains exact counts and first IDs; the independent artifact review retains complete kill-ID hashes. All controls emitted the full input denominator; none was credited by a fabricated partial-row count.

The native producer re-admitted the complete 649-byte FDE/CIE, 169-row contiguous byte listing, all five dynamic call sites, actual read-only 64-byte ASCII-zero literal/two RIP bindings and absence of fixed helper edges. It scanned all 80,300 actual 8-byte RELA write intervals (including partial overlaps), rejecting code/data writes. It bound actual native decimal operands and checked fixed integer expressions across all 65,536 values; this has no PC/register/simulated-memory/opcode evaluator. Fourteen below-whole-image-digest code/data/FDE/RELA corruptions and seven exact canonical comparator controls passed. Raw code is never executed. The native GNU listing and argv use an explicit owned-file display placeholder for the transient disassembly filename; body/data bytes and recorded runner stdout/stderr are not normalized.

The runner recorded 53 compiler/program/identity calls and 106 stdout/stderr streams; native binutils subprocess argv/version/stderr/listings are separately retained in the native report. All 10,846 tracked physical inputs (including modes), seven actual pinned repository heads/trees/statuses, 103 admitted provider payloads, two actual installed component manifests, exact target/archive and resolved GCC/BFD/runner identities were unchanged before/after. Ambient compiler/linker injection variables were excluded without recording their values.

An independent peer rehashed every recorded call/stream, recomputed full canonical outputs and all mutant kill sets, verified native/data/relocation/provider/audit closure and raw rebuild equality, then reran both existing clients using only the raw input path. Both fresh replays matched all 69,359 rows and 90,453 callbacks with exit 0/empty stderr. The exact original four replay gzip streams are preserved under `.gzip-bytes` suffixes (not recompressed), accompanied by their original receipt/script.

The same exact corrected clean source head then passed `make doctor`, `make verify`, `make catalogue-check` and `make reproduce`, all four exits 0/eight streams, with the full before/after map identical to the actual experiment. The separately retained static wrapper only runs those four vetted targets. No test discovery or expanded evaluator suite was launched.

## Failure chronology and lossless raw evidence

The initial clean pushed `f2149dcd44ac4577b5f754aa2276d4b504c28873` run is FAIL, not current validation. It stopped after 41 recorded calls / 82 streams at a runner mutation occurrence guard: expected four literal `return 1;` sites, actual source had five. Its before/after map was unchanged. Only the runner's expected count changed 4 to 5; an independent peer recounted every mutation occurrence before the distinct full corrected run. Rust, driver, native producer and frozen authority were unchanged. Original partial output was not reused as current PASS.

`actual/FAILED-PREPARATION-RAW-TRANSPORT.json` retains all 101 original failed-preparation files, including original runner and41/82 streams (183,867,994 original bytes). Its launcher stderr was visible in the execution tool but not locally captured; `INITIAL-RUN-GUARD-FAILURE.json` is explicitly an authored explanatory record. The corrected launcher streams are locally retained. `actual/ACTUAL-RAW-TRANSPORT.json` retains 128 files / 43 unique contents, 246,252,916 original bytes, including every 53 / 106 stream, both audit maps and native/control exports. `static/STATIC-RAW-TRANSPORT.json` retains 12 files/eight contents,5,035,913 original bytes. Transport compression has no normalization, and shared external content is restricted to the two exact frozen input/expected paths. Runnable libraries/clients/full ELF images are excluded; bounded native body/literal evidence is included.

## Reproduce

At the exact clean corrected checkpoint with the admitted physical inputs/provider, the original runner command was:

```sh
env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tools/validate_parts_writer649.py --root /tmp/hl-resume-20261101/selector-56c --output /tmp/hl-resume-20261101/writer649-build-51c0ea7f --head 51c0ea7fc4a035b4c0dd690f9310657b39ea9db4 --core-archive /tmp/hl-resume-20261101/toolchain/prefix/lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib
```

Use a fresh output path to reproduce; the runner refuses to overwrite originals. Exact compiler/linker arguments, versions, environment and raw results are in `actual/CALLS.json`/transport. `static/static_checks.py` retains the exact four-target wrapper, with original commands/streams/audits. `CURRENT-SOURCE.json` binds all four unchanged execution files from the actual source head to this evidence-only child. `REPRODUCE-FROZEN.md` explains lossless authority decompression, v1-prefix derivation and the original independent scripts' fixed native layout, without restamping historical pre-source independence. Provider/pin/source admission is required; no automatic download or new dependency graph is implied.

## Limits and next question

The current full suite, expanded evaluator families, captured execution, hosted CI, full node build, invalid aliases, mutable descriptor/parts, renderer/private ABI, unwind/fault and concurrent callbacks remain outside authorization or proof. The finite corpus does not exhaust part sequences or astronomically large successful zero-run traces; the complete structural theorem handles admitted finite u64 runs. All acceptance gates remain false. No byte-window registry change is made for an extent-rejected official candidate. New authored work is MIT; `third_party/NOTICE.md` preserves separate artifact rights.

The next distinct question is the already bounded outer 602 padding routine's descriptor/header mutation and restoration rules. It is not implemented or counted here.
