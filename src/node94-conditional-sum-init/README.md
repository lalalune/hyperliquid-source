# Node94 signed-low32 initializer

Independent safe `no_std` reconstruction of complete linked-VA interval
`[0x5475e80,0x5475ead)` in node94. `initialize` writes four little-endian qwords
`[0, RSI + sign_extend(low32(RDX)), 0, sign_extend(low32(RDX))]`, with wrapping
64-bit addition. It returns full RAX=1, final RSI and unchanged full RDX.

The byte image must have a nonwrapping numeric address interval and contain the
complete 32-byte output. Unaligned and exact-end spans are admitted. Invalid
spans return `None` without changing the image. Numeric addresses are never
converted to host pointers. This is an ordinary-memory final-state projection;
native faults, ABI, flags, MMIO, races and control-stack aliases are excluded.

The complete proof, pre-Rust oracle, frozen fixtures, native observations and
independent review are in
`research/work-items/RE-004-conditional-sum-init-rust-94/README.md`.
The input-only driver is a qualification client, not an original node executable.
