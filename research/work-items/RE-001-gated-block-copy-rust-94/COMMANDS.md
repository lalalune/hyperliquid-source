# Commands and tools

Working directory: repository root. No captured binary was executed. `static_evidence.py`
uses `tools/elf_index.py` and `tools/fde_extents.py` to parse authenticated bytes.
For every complete window in its `WINDOWS` map it invokes:

```
/opt/homebrew/opt/binutils/bin/objdump -d --start-address=START --stop-address=END artifacts/node/94/hl-node
/usr/bin/objdump -d --start-address=START --stop-address=END artifacts/node/94/hl-node
/opt/homebrew/opt/binutils/bin/objdump --dwarf=frames artifacts/node/94/hl-node
```

The frame stream is read incrementally and only complete bound FDE/CIE records
are retained. No partial caller disassembly is substituted for complete windows.
The static outputs include their original headers/options-independent labels;
nearest-symbol labels are not used to infer identity.

Actual initial sequence:

```
git fetch origin main
git switch -c research/node94-gated-block-copy-rust origin/main
python3 -O research/work-items/RE-001-gated-block-copy-rust-94/static_evidence.py --out research/work-items/RE-001-gated-block-copy-rust-94/static
python3 -O research/work-items/RE-001-gated-block-copy-rust-94/oracle.py --freeze
```

The last command ran before any new component source existed. Rust was then
written independently from the proved relation. Formatting preceded native
validation. `logs/build-note.log` preserves the corrected PATH and CIE-control
ordering failures. Successful complete native run:

```
python3 -O research/work-items/RE-001-gated-block-copy-rust-94/verify.py --out work/gated-block-copy/native-final-2
```

`native/commands.json` records every actual compiler argv, cwd, exit and output.
Builds pin Rust 1.94.1, edition 2024, opt0/3, codegen-units=1,
overflow-checks=yes, panic=abort, debuginfo=0, warnings denied and stable remapped
build paths. The compiled input-only clients receive only decompressed
`fixtures/inputs.tsv.gz` on stdin. Expected rows are read solely by Python's
comparator. Native outputs were archived exactly, then losslessly deduplicated
by complete line after the successful run; `native/packing.json` records that
packaging operation. Current verifier writes that same schema directly. No
reconstruction binary, oracle, expectation or output value changed in packaging.

Global and focused commands are listed in README and their exact stdout/stderr
is under `logs/`. No normalization mask, captured execution, emulation, hosted
CI, container result or full-suite result is claimed. No external data other
than public read-only GitHub overlap queries and the pinned artifact was used.
