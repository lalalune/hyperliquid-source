# node94 BSR ladder value projection

`ladder(value, second, third, fourth) -> Option<u32>` reconstructs the
unsigned numeric relation in node #94 ELF VA `[0x556e980, 0x556e9d8)`.
All four arguments represent the low 32 bits of the original registers;
their application meanings are unknown.

`None` excludes `second <= 1` or `third == 0`, where the original unguarded
`BSR` instructions have an architecturally undefined destination. This is
the safe API's refusal to specify a value, not recovered target behavior.
On admitted inputs the function uses wrapping subtraction, a zero default
of 11, and the observed ordered min/max operations. It always returns
`Some(5..=12)`. The two inner bounds may be inverted, so replacing the
sequence with a conventional clamp changes behavior or can panic.

The library is independently authored MIT Rust, `no_std`, with no external
dependencies or unsafe code. It is built directly by pinned rustc 1.94.1;
there is no Cargo workspace, dependency lockfile, original ABI claim or
recovered crate identity. The separate input-only client uses the host
standard library solely to read TSV inputs and print numeric results.

From the repository root:

```sh
python3 research/work-items/RE-004-node94-bsr-ladder-rust/validate.py
```

See the [evidence packet](../../research/work-items/RE-004-node94-bsr-ladder-rust/README.md)
for target bytes, frozen expectations, build commands, compiled negative
controls and limits. Validation executes only the newly built Rust client.
