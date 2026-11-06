# Frozen Node115 storage-key suffix relation

Task RE-011. Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are unrebased ELF virtual addresses.

The bounded native extent is `0x3d47d20..0x3d47ebb`, including its unwind
cleanup records. The selected normal relation builds a 52-byte allocation:

1. copy 20 source address bytes from input object offsets `+0x20..+0x33`;
2. load qwords at offsets `+0`, `+8`, `+0x10`, and `+0x18`;
3. byte-swap each qword; and
4. emit them in reverse source order at suffix offsets
   `+0x14`, `+0x1c`, `+0x24`, and `+0x2c`.

Logically, for address `A` and source qwords `w0..w3`, the suffix is:

```text
A[0..20] || be(w3) || be(w2) || be(w1) || be(w0)
```

The independent Rust API accepts exactly those logical values and returns
either the suffix or `prefix || suffix`. The native function's runtime prefix,
allocator implementation, source types, ABI, unwind behavior, surrounding
adapter, actual storage backend and response serialization are not claimed.
Pointer aliasing, allocation failure, malformed object layouts and arbitrary
runtime prefixes are outside the frozen domain.

The 258 committed `key-vectors.tsv` rows from
`RE-011-storage-read-115` are frozen input/output cases. They are a static
model generated before this Rust implementation, not captured target execution.
