# node94 container pop/retreat value component

This dependency-free `no_std`, safe Rust library reconstructs the complete
87-byte node94 leaf `[0x5178be0,0x5178c37)`. It updates a caller-provided
byte image and returns the full numeric RAX. The equal branch preserves
the original top-store-before-popped-load order, including partial overlap.

```rust
pub fn transition(
    image: &mut [u8], image_base: u64, object: u64,
) -> Result<u64, AccessError>;
```

Numeric addresses and qword arithmetic wrap modulo 2^64. The image itself
must not wrap. Every required span is admitted before any write; errors
leave the image unchanged. `object` itself and the returned numeric value
need not identify an accessible byte. There is no arbitrary counter cap,
alignment requirement or inferred container layout beyond accessed fields.

This is a memory/RAX value projection under stable ordinary memory, not
the original ABI, register clobbers, fault ordering or whole-node code.
See [the proof](../../research/work-items/RE-004-container-pop-rust-94/PROOF.md)
for the complete domain, equations, alias argument and exclusions.

The qualification pins rustc 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`),
the actual compiler executable SHA-256 and the aarch64-apple-darwin host.
No Cargo workspace, dependency resolution or captured binary execution is
needed. From the repository root, using a fresh output directory:

```sh
python3 -B research/work-items/RE-004-container-pop-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/container-pop-rust/replay
```

The verifier invokes the real compiler with opt-level 0 and 3,
`-Coverflow-checks=on`, `-Dwarnings`, one codegen unit and the explicit
`/usr/bin/cc` linker. `input_only_driver.rs` is a separate std host client;
it embeds no expected answers. Full recipes, raw evidence, repetitions,
mutants and limitations are in the linked packet.
