# Replay and observed results

Run from the repository root. Review the code first. The static tools read the
captured ELF as data and invoke only a caller-admitted GNU objdump; they never
execute it. The Rust commands compile and run only the new authored safe source.
Use fresh output directories and an already installed Rust 1.95.0 toolchain.
No Cargo download, target execution, emulator or full repository test suite is
required.

```sh
packet=research/work-items/RE-012-node115-logical-header-writer
python3 -I -B -S "$packet/collect.py" --target artifacts/node/115/hl-node --objdump /path/to/gnu/objdump --output /tmp/header-native-fresh --check "$packet/observed"
python3 -I -B -S "$packet/controls.py" --target artifacts/node/115/hl-node --evidence "$packet/observed" --output /tmp/header-controls-fresh
python3 -I -B -S -O "$packet/controls.py" --target artifacts/node/115/hl-node --evidence "$packet/observed" --output /tmp/header-controls-opt-fresh
```

`collect.py` authenticates the entire input, eight full FDE bodies, raw CFI,
control transfers, data spans, RELA records and import binding. The recorded
results are 4,659 bytes / 1,145 instruction rows, 181 control transfers, 36 calls,
39 RIP edges, 97 selected bindings among 61,001 RELA records, two imports, 81
builtin names and six source Locations. Replay permits only tool version/hash
provenance changes; native bytes and semantic records must match exactly.
The 121 static controls include 48 named operand-byte mutations and structural,
import, data, mocked failure and replay controls. Mocked subprocess failures are
synthetic controls, not observed GNU failures.

For an own-source host replay, create a fresh build directory and a separate
empty execution directory. Pass the chosen installed compiler and sysroot
explicitly. The input-only probe has no expected results and reads no files;
`expected.tsv` is compared by the parent, outside its working directory.

```sh
crate=src/node115-http-header-writer
packet=research/work-items/RE-012-node115-logical-header-writer
build=/tmp/header-rust-fresh
mkdir "$build" "$build/empty"
rustc --edition 2024 -D warnings --crate-name node115_http_header_writer --crate-type rlib -C opt-level=0 "$crate/src/lib.rs" -o "$build/libwriter.rlib"
rustc --edition 2024 -D warnings --test "$crate/tests/frozen_cases.rs" --extern "node115_http_header_writer=$build/libwriter.rlib" -C opt-level=0 -o "$build/tests"
(cd "$build/empty" && ../tests --test-threads=1 --color never)
rustc --edition 2024 -D warnings "$packet/validation/input_probe.rs" --extern "node115_http_header_writer=$build/libwriter.rlib" -C opt-level=0 -o "$build/probe"
(cd "$build/empty" && ../probe) > "$build/actual.tsv"
cmp "$packet/validation/expected.tsv" "$build/actual.tsv"
```

Repeat with opt-level3 and fresh output names. The retained actual invocations
also pin the installed sysroot and remap build paths. Literal cases were frozen
before production source: 42 small cases (29 success, 13 refusal) plus four real
65,535/65,536-group count plans. Oversized arithmetic remains a source argument;
no forged slice or native allocator outcome was used.

[EXACT-EDITS.json](mutations/EXACT-EDITS.json) pins the twelve safe variants,
replacement counts, resulting source hashes and named witnesses. Apply each only
to a copied library, compile it and the unchanged input-only probe, and require
normal exit and all 46 canonical ordered records before comparing values.
[PROBE-PROTOCOL.md](validation/PROBE-PROTOCOL.md) defines framing and the strict
parent comparator. Compiler errors, panic, timeout or malformed output do not
count as semantic detections. The exact reviewed qualification driver and its
final readback are retained as audit text in validation; absolute paths are
explicit role tokens, not executable replay commands.

Observed Rust results: debug46 and release46 passed, both probes exact, all12
normal variants detected at their named witnesses, and comparator10 malformed
controls rejected. The final two compile-only x86_64 Linux rlibs are identical,
93,536 bytes, SHA-256
`b9071dad4da64ca3d460b7eefe0cd8f301b96aca2270154f0a4a205adb06ab21`.
The first two Linux outputs used different basenames, so their ar name tables
and whole-file hashes differed; their rmeta and object members were identical.
Both original results remain recorded. This build hash is not captured-byte
coverage.

Receipt bundles retain actual commands and stream bytes as UTF-8 JSON strings,
with original/stored hashes. Encoding each decoded `text` value as UTF-8 recovers
its stored stream exactly. Only declared path token substitutions apply; streams
have no EOF normalization. The generated Rust test/probe each lost exactly one
surplus terminal LF before qualification; the original and qualified hashes are
recorded separately. All sources and evidence are bound by MANIFEST.sha256.

The first staged whitespace check reported preserved unified-diff blank context
lines and TSV records whose final buffer field is intentionally empty. Those
bytes remain unchanged; narrowly scoped .gitattributes rules exempt only those
formats. The first diagnostic is retained with the repository check receipts.
