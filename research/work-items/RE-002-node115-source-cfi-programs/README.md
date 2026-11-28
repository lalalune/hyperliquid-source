# RE-002: Source call frame instruction programs in node #115

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The compiled object relocation identifies each source function’s frame record. The verifier compares the common CIE initial instructions and all 29, 24 and 25 FDE instruction bytes for Big32 digit multiplication, reverse byte search and the statx helper respectively. It checks equal code/data alignment factors and return address registers. The retained checks concern these unwind records, separate from previous code and LSDA comparisons.

Provision the offline cache using RE-002-node115-umodti3-source-build. Rebuild std and panic_unwind with one codegen unit and explicit frame pointers. Run from the repository root with Python 3.12 and GNU binutils 2.42.

```sh
python3 -B research/work-items/RE-002-node115-source-cfi-programs/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the captured ELF and source objects as data. The retained log records the selected comparisons and changed-byte control.
