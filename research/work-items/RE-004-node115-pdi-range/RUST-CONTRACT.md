# Frozen Node115 PDI range iterator contract

Task RE-004. Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All native addresses are unrebased ELF virtual addresses.

The selected body is `0x22b3160..0x22b3298`, 312 bytes, SHA-256
`9d5a5e84ae58cbf70584e42af0321270acd95aca7af1edf7e69a8cfb8707ce19`.

For input words `start`, `end` and `base`, the selected relation is:

```text
count = max(end - start, 0)                 // unsigned subtraction
count <= 2^60 - 1                           // 8*count allocation admission

for 0 <= index < count:
    product = base * 10000                  // checked u64
    value = product + start + index         // checked u64
```

The native function allocates an eight-byte element for every generated value.
It can leave a partially populated allocation if a later multiplication or
addition overflows. The independent Rust API is a fallible streaming iterator:
it performs no allocation, yields all values before the first arithmetic error,
yields that error once, and then terminates. It does not claim the native
allocation, partial-buffer contents, panic behavior or return layout.

The safe API also rejects a range count above the native admission bound before
iteration. Start/end inversion is the observed empty-range relation, not an
error. Asset names and units remain inferred.
