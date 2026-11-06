# Node #115 book-order slab unlink

Dependency-free `no_std` model of the two 860-byte removal bodies at
`0x58dfbc0` and `0x58dff20` in Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The model covers the vacant return, free-list push, saturating counter,
defined event fields, saturating quantity subtraction, null level,
negative `+0xb0` stop, cached level-link replacement, and the link
rewrite used when element byte `+0xd8` is zero. A nonzero `+0xd8`
returns before the native call at `0x4de02d0`. A full event collection
returns after the free-list update, before the native grow callee.

Direct `rustc` 1.95.0 / edition 2021. No Cargo manifest is invented.
This is not a whole-book matcher and it does not close an order-book
acceptance gate. Evidence: `research/work-items/RE-006-node115-book-order-unlink`.

```sh
rustc --edition 2021 --test -D warnings src/node115-book-order-unlink/lib.rs -o work/book-order-unlink-test
./work/book-order-unlink-test
```
