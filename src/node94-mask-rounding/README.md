# Node94 mask-rounding value

`bound_value(u64) -> u64` independently reconstructs the raw return value of
node #94 ELF VA `[0x555e610, 0x555e65b)`. The target SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This safe, dependency-free `no_std` component has one value API:

```text
n > 0xff00ff00ff00feff: 0xffffffffffffffb8 (the bits of signed -72)
otherwise: n + floor(n/256) + (n < 131072 ? floor((131072-n)/2048) : 0)
```

The arithmetic in the capture is modulo `2^64`. The inclusive cutoff keeps
every admitted result between 64 and `2^64-3`, so no admitted addition wraps
and the capture's internal zero-to-sentinel conditional move is unreachable.
The implementation retains explicit wrapping additions and omits that dead
conditional. The subtraction is evaluated only where its input is in range.

The raw value `0xffffffffffffffb8` is **not an exclusive error indicator**:
admitted input `0xff00ff00ff00feba` also produces it. A `Result` or `Option`
based only on that return word would invent a distinction the leaf does not
provide. No original function name, compression library/version, units or
error meaning is asserted by the analytical name `bound_value`.

The [proof and evidence](../../research/work-items/RE-004-mask-rounding-rust-94/README.md)
cover every bit pattern as a value contract under normal return conditions.
The API uses a new Rust ABI; original registers, flags, unwind/CET behavior,
caller allocation policy and the complete surrounding component are outside
scope. No captured instructions or unlicensed inferred code are included in
the implementation.

## Actual standalone build

No Cargo workspace, dependencies, install hooks or invented lockfile are
needed. The recorded research compiler is rustc 1.94.1,
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, for `aarch64-apple-darwin`.
The verifier checks its actual executable SHA-256 and records the linker.
From repository root, using a fresh ignored output directory:

```sh
RUSTC_BIN=$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)
python3 -B research/work-items/RE-004-mask-rounding-rust-94/verify_rust.py \
  --out work/mask-rounding-review --rustc "$RUSTC_BIN"
```

The native client consumes little-endian u64 records on stdin and emits one
little-endian u64 per input. It receives no expected answers, embeds none,
and opens no files. Its comparison parent owns the frozen oracle. This is
data-flow separation, not a filesystem sandbox. Partial input records fail
before any output. The native checks execute only newly authored Rust.
