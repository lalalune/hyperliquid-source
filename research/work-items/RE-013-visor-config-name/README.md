# RE-013: Visor config-name low-byte relation

This static packet resolves the separate Visor conversion leaf left opaque by #1516. Under stable valid input bytes and immutable code/table premises, AL selects one of79 exact byte names; other inputs return0x4f. NvTestnet is0x21. No whitespace normalization, JSON, application fallback or full-register/ABI behavior is inferred. The similar node94 work #1385 targets a different capture and76values; no source/data was copied from it.

Target: SHA256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`, base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Coordinates are original linked ELF virtual addresses. PROOF.md addresses the guard, table, every input read, literal/register liveness and all80 ordinary returns.

With an authenticated non-executable capture at `$BINARY`, reproduce in this directory using fresh output paths:

```sh
python3 -B survey.py --binary "$BINARY" --output fresh-observed
python3 -B verify.py --binary "$BINARY" --receipt fresh-integrity.json
python3 -B check_bindings.py --binary "$BINARY" --receipt fresh-bindings.json
python3 -B audit_literals.py fresh-literals.json
python3 -B audit_cfg.py fresh-cfg.json
python3 -B check_language.py fresh-model-output
python3 -B crosscheck_llvm.py --binary "$BINARY" --output fresh-independent
```

The verifier regenerates twice and checks the retained observed records. Audit scripts read the retained observed native listing; compare a regenerated observed directory byte-for-byte first when reproducing. Repeat with `python3 -O -B`. All output writers preserve existing files. FROZEN-CORPUS.json pins the263148-case synthetic corpus frozen before any implementation; regenerate it with check_language.py and compare its compressed/uncompressed digests. It need not be committed as a large binary. Byte-fragment predicates and exact lookup are high-level supporting models, never a CPU/target comparator.

VALIDATION.json records actual root/static checks, source hashes and normal/optimized receipt equality. Full make test is NOT RUN because flat discovery includes captured-instruction evaluators outside authorization. No Rust compiler is installed in the retained remote runtime; no compiler was installed and no Rust implementation/build is claimed for this static contribution. No hostedCI, target execution, networking or component gate change is claimed. The instruction identity inventory is not a count of semantic proofs or recovered bytes.

New code/docs are independently authored MIT work. Target evidence retains upstream rights. Frozen prequalification statuses are retained as provenance; the current bounded claim and its limits are in PROOF.md.
