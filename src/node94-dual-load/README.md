# node94 dual load

Independent MIT, dependency-free `no_std` Rust reconstruction of complete
node94 `[0x4e48600,0x4e4861d)`. The function returns the raw RAX/RDX pair
for a copied input byte and numeric load bias. It closes all 127 RELATIVE
relocations in the B window and retains its other 129 raw file words.
Both complete 256-word reachable windows are pinned; their logical source
types and extents remain unknown. See the [proof](../../research/work-items/RE-004-dual-load-rust-94/PROOF.md)
for mapping, stability and loader premises.

The constants are numeric observations from authenticated ELF data and
relocation records. There is no copied inferred source, target instruction
transplant, dynamic loader or unsafe pointer API. Native qualification is
a direct rustc build, without a root Cargo workspace or dependencies:

```sh
python3 -O -B research/work-items/RE-004-dual-load-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/dual-load-review
```

Use a fresh output directory and the recorded macOS aarch64 compiler and
linker for exact qualification. The input-only client reads nine-byte
rows `(index:u8,load_bias:u64 little-endian)` and writes 16-byte rows
`(RAX:u64,RDX:u64 little-endian)`. It never receives expectations and
rejects incomplete input before output. Only this new client executes.
