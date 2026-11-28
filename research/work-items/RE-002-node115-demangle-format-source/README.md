# RE-002: qualify node #115 Rust v0 demangler formatting linkage

Target Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860, rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363. The sysroot lock selects rustc-demangle 0.1.27.

The release-source build with one codegen unit and explicit frame pointers emits an 86-byte v0 demangler skipping_printing instance that matches the selected node #115 body at ELF VA 0x5c48892 outside its five real relocation fields. The direct print_path edge, both location addresses and the linked unwrap diagnostic slot resolve. The 61-byte source literal section equals the referenced target data. This qualifies the selected source build and does not infer global compiler settings, validate the location records, or execute either the demangler or node.

Provision the cache as described in RE-002-node115-umodti3-source-build. Run from the root using Python 3.12+, Rust/Cargo 1.95.0 and the GNU binutils directory (ar, nm-new, objdump, objcopy and readelf):

```sh
python3 -B research/work-items/RE-002-node115-demangle-format-source/verify.py /path/to/cache /path/to/binutils
```

The offline log records all five fields and the changed-byte control. No registry or gate changes.
