# node94 scalar-sum normalization

Independent safe, dependency-free `no_std` Rust for node94 ELF VA
`0x565eaa0..0x565ec0b` (363 bytes). `normalize` first stores both scalar words,
then reads two 256-bit operands, forms their corrected 320-bit sum, extracts
31-shifted bits and conditionally negates the 256-bit result. It returns full
numeric RAX/RDX/RCX together with the in-place destination effect.

Negative scalar times zero retains the target's separate `-magnitude*2^256`
correction. The sum wraps at 320 bits before its sign is selected. The output
is the absolute floor quotient by `2^31`, reduced to 256 bits; the returned
scalar values are independently negated only for that wrapped negative sign.
No conventional signed-product or nonzero-operand invariant is substituted.

The 64-byte source and 32-byte destination must fit in one nonwrapping image.
Any partial/unaligned alias is accepted, with operand values read after the
initial scalar stores. Both spans are validated before any write; refusal
leaves the image unchanged. Every scalar/operand bit is admitted. Native faults,
MMIO, concurrency, control-memory aliases, other registers and the original
calling convention are outside this safe projection.

See the [proof](../../research/work-items/RE-001-scalar-normalization-rust-94/PROOF.md)
and [evidence packet](../../research/work-items/RE-001-scalar-normalization-rust-94/README.md).
No captured code or emulator ran; no unlicensed implementation was copied.

```sh
cargo +1.94.1 check --manifest-path src/node94-scalar-normalization/Cargo.toml --locked --offline
python3 -O research/work-items/RE-001-scalar-normalization-rust-94/verify.py --out work/scalar-normalization-replay
```

The input-only client accepts TSV columns ID, image base, source address,
destination address, x, y and image hex (`-` for empty). Numeric inputs are hex
u64. It reports refusal or full register values and every changed image byte.
Expected values remain in the external Python comparator. This standalone
component does not establish a node workspace or native calling convention.
