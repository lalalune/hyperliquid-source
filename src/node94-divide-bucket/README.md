# Node94 divide-then-log2 bucket

`bucket(dividend: u64, divisor: u64) -> Option<u8>` is an independently authored
safe `no_std` value API for the complete node #94 leaf at ELF VA
`[0x4f9eb10, 0x4f9eb82)`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

For a nonzero divisor, let `q = floor(dividend/divisor)`. The API returns
`Some(0)` for q=0 or 1, otherwise `Some(min(floor(log2(q)),6))`. Its integer
leading-zero calculation implements the proven relation independently of the
capture's five separate shifts and arithmetic cap.

`None` is a newly chosen refusal for divisor zero. The captured unsigned DIV
has no normal return for that input; it has no recovered error value or Option
type. The new API refuses before division, including `(0,0)`. All nonzero
divisors, including high-bit values, are admitted. No signed interpretation or
implicit narrowing is applied.

The [proof and evidence](../../research/work-items/RE-004-divide-bucket-rust-94/README.md)
bind the complete 114-byte FDE, internal NOPs, actual direct caller and its
constant divisor `0x80000`. The caller's purpose and what the bucket represents
remain unknown. `Option<u8>`, its Rust ABI and the client's byte protocol are
new interfaces; original registers, flags, traps/unwind behavior and full
component identity are outside scope.

## Actual build

The component has no dependencies, unsafe code, install/build hooks, root Cargo
workspace or invented lockfile. The recorded research build uses actual rustc
1.94.1, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, target
`aarch64-apple-darwin`. From repository root, with a fresh output directory:

```sh
RUSTC_BIN=$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)
python3 -B research/work-items/RE-004-divide-bucket-rust-94/verify_rust.py \
  --out work/divide-bucket-review --rustc "$RUSTC_BIN"
```

The verifier enforces the compiler executable hash and records its full version,
linker identity, flags and sources. Opt0 and opt3 use overflow checks and deny
warnings. Only newly authored Rust is executed.

`input_only_driver.rs` reads consecutive little-endian `(u64,u64)` pairs from
stdin. It emits `[0,0]` for refusal and `[1,bucket]` for an admitted input.
That validation protocol is not recovered target wire format. The client
neither embeds expected values nor opens files; its parent owns the separately
frozen oracle. This is data-flow separation, not a filesystem sandbox. Partial
input pairs fail before any output.
