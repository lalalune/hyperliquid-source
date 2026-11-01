# Node #94 compression-bound values

This independently authored, dependency-free `no_std` Rust library implements
the two arithmetic contracts established by the captured node #94 leaves:

| API | Input domain | Return value | ELF VA interval |
| --- | --- | --- | --- |
| `snappy_bound(u64) -> u64` | All raw 64-bit values | `(n + floor(n/6) + 32) mod 2^64` | `[0x546af50, 0x546af6b)` |
| `lz4_bound(u32) -> u32` | All raw 32-bit values | `0` above unsigned `0x7e000000`; otherwise `n + floor(n/255) + 16` | `[0x546e280, 0x546e2ad)` |

The names are inferred library roles. The full target SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The [evidence packet](../../research/work-items/RE-004-compression-bounds-rust-94/README.md)
revalidates every body byte, the FDE extents, padding, immediate constants and
absence of body relocations. It proves the arithmetic for both complete input
domains, separately from the finite native validation corpus.

The first API deliberately wraps. Its result is not a usable allocation bound
for every `u64`. The second API exposes the original input bits rather than
an `i32`: for example, `lz4_bound((-1_i32) as u32)` returns zero. No input is
implicitly truncated from `usize` or `u64` by this API.

These safe value functions choose a Rust ABI. They do not expose original
symbols, Linux x86-64 register clobbers, unwind behavior, CET behavior, or a
compressor. They do not recover original library versions or a complete
storage/transport component. No unlicensed inferred source was read or copied.

## Standalone build

There are no package dependencies, install hooks, Cargo workspace or invented
lockfile. The recorded research compiler is rustc 1.94.1
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, host `aarch64-apple-darwin`.
This is a native value check on macOS, not an original Linux build.

From the repository root, resolve the installed compiler without installing
or changing a toolchain, then use a fresh ignored output directory:

```sh
RUSTC_BIN=$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)
python3 research/work-items/RE-004-compression-bounds-rust-94/verify.py \
  --out work/compression-bounds-review --rustc "$RUSTC_BIN"
```

The verifier pins the actual compiler executable hash and records compiler,
linker, flags, source hashes, inputs and all subprocess results. It builds
rlibs, unit tests and an independent input-only executable at optimization
levels 0 and 3, with overflow checks enabled. It repeats both builds and
requires raw equality of each rlib and linked executable. It also compiles
eight deliberately wrong implementations at both optimization levels.

`input_only_driver.rs` reads `id operation input_hex` records from standard
input and emits `id result_hex`, with exactly 16 lower-case hexadecimal digits
for the result. It neither embeds expected values nor opens an expectation
file. This separates data flow; it is not a filesystem sandbox. The frozen
expectations and the parent comparator remain in the evidence packet.
