# Node #94 strided-array sum

This safe, dependency-free `no_std` library reconstructs the returned value of
`[0x52cfe00,0x52cfe4d)` in node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Names describe observed operations; original symbols, types and table meaning
remain unknown.

`strided_sum(table: &[u64], index: u32, field: u32) -> Option<u64>` sums
`table[index + row*6600]` for `2^(field & 63)` rows, modulo 2^64. The count is
always positive. `Some(0)` is a valid sum. `None` is a newly chosen refusal
when the required span is unrepresentable or the supplied slice is too short;
the target has no corresponding refusal branch.

`required_words(index, field) -> Option<usize>` returns the exact minimum
contiguous length, `index + (2^(field&63)-1)*6600 + 1`, when its byte size fits
Rust's `isize::MAX` object bound on this platform. All checks happen before any
element read. No arbitrary count cap is imposed; theoretical representability
is independent of available RAM. The host driver limits only its test allocations.

The original zero-extends ESI, reloads the base qword at RDI+0x60 and count dword
at RDI+0x68 every iteration, and permits wrapping effective-address arithmetic.
The slice relation assumes stable ordinary fields/table, a valid contiguous
span including intervening words, nonwrapping addresses and valid normal-return
state. It excludes changing fields, sparse mapped memory, address-wrap cases,
faults, volatile reads and original pointer/register/stack ABI. The slice is a
view of decoded little-endian word values; this is not an ABI wrapper.

The pinned research build uses direct rustc 1.94.1, with no dependencies or
invented Cargo workspace/lockfile. The input-only std driver materializes real
tables from compact descriptors. Full proof and reproduction commands are in
[the evidence packet](../../research/work-items/RE-004-strided-array-sum-rust-94/README.md).

```sh
python3 research/work-items/RE-004-strided-array-sum-rust-94/verify_rust.py \
  --rustc "$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)" \
  --out work/strided-array-sum-review
```

Use a fresh output directory. Tests run new Rust on aarch64 Darwin, not captured
instructions or an emulator. Original Linux x86-64 compiled-byte identity is
unmeasured; no foundation completion gate changes.
