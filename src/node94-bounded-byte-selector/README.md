# node94 byte selection and stored-byte equality

Independent, dependency-free `no_std` Rust for the complete node94 selector `[0x4ff8ac0,0x4ff8b28)` and its direct equality wrapper `[0x5004e70,0x5004ea1)`. Target SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`select_byte` projects the cached-byte shortcut, empty-span default, index-zero shortcut and signed wrapping low32 clamp onto an immutable image. The stored pointers need not delimit a conventional array. Successful `u8` results represent the selector's complete zero-extended RAX. Disabled selection reads nothing, including no image-range validation.

`matches_stored` closes the actual wrapper call: it eagerly reads the inner bound, selects a byte, then compares the stored byte. Since the selector zero-extends every result, the wrapper's full RAX is exactly the returned Boolean's 0/1 value. The predecessor had established only AL while the callee remained unknown.

All addresses are abstract `u64` values over one `&[u8]`. Missing actually used ranges return `Unavailable`. Fixed field additions and the image extent may not wrap; the selected data address retains modulo-2^64 addition. No writes occur. Ordinary stable memory and disjoint native control storage are premises. Pointer ABI, fixed-field wrap, faults, concurrent/MMIO effects and stack/control aliases are not reproduced. This is a value projection, not a callable replacement for captured machine code.

From the repository root:

```sh
PATH=/opt/homebrew/opt/rustup/bin:$PATH cargo check --offline --manifest-path src/node94-bounded-byte-selector/Cargo.toml
python3 -O research/work-items/RE-001-bounded-byte-selector-rust-94/verify.py --out work/bounded-byte-selector-review
```

The standalone client accepts inputs only. It neither embeds nor opens expected outputs. See the evidence packet's `PROOF.md` for the complete relation, access domain and exclusions; `COMMANDS.md` records exact qualification commands and limits. No full-node build, original source identity or gate completion is claimed.
