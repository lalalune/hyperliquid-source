# RE-002: Plain character display in node #115

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The 183-byte char Display implementation at 0x168a370 is matched against the official Rust release. The verifier checks the FDE extent and the selected formatting reference. This verifies the plain character representation separately from Debug escaping.

Provision the offline cache using RE-002-node115-umodti3-source-build. Rebuild core with one codegen unit and explicit frame pointers. Run from the repository root with Python 3.12 and GNU binutils 2.42.

```sh
python3 -B research/work-items/RE-002-node115-char-display-source/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the capture as data. The retained log records the FDE extent, body comparison outside source relocation fields, the selected resolved destinations, and the changed-byte control.
