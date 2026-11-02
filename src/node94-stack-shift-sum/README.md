# Node #94 stack shift sum

`shift_sum(flag: u32, first: u32, second: u32) -> u64` is a safe, dependency-free
`no_std` value reconstruction of `[0x55c6c40,0x55c6c77)` in node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The names describe observations; the original type, symbol and library are unknown.

All u32 triples are admitted. A flag other than exactly 1 returns 0. For flag 1,
the result is

```text
(2^(max(first-second,0) mod 64) + 2^(3 + first mod 64)) mod 2^64
```

The subtraction above is mathematical. Rust uses unsigned saturating subtraction,
wrapping u64 shifts and wrapping addition. In particular, `(1,124,61)` returns 0;
zero must not be interpreted as an error or as proof that the flag was inactive.

The target reads u32 words at entry RSP+8, RSP+12 and RSP+16, returns RAX, and
only reads the latter two words when the flag equals 1. This API receives values
through the Rust ABI. It does not reproduce the original stack layout, register
clobbers, conditional memory reads, inaccessible-memory faults or return-address
behavior. The behavioral claim concerns normally returning target states with
all required memory readable, and an ordinary valid return address.

The component has no dependencies, Cargo workspace or invented lockfile. Its
build is direct `rustc`, pinned to the actual compiler executable and version in
[the evidence packet](../../research/work-items/RE-004-stack-shift-sum-rust-94/README.md).
The input-only std client is a host harness, not part of the no_std library.

```sh
python3 research/work-items/RE-004-stack-shift-sum-rust-94/verify_rust.py \
  --rustc "$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)" \
  --out work/stack-shift-sum-review
```

Use a fresh output directory. Native aarch64 Darwin value tests and repeated
builds do not establish original Linux x86-64 ABI or compiled-byte identity.
