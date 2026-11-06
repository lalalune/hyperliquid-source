# RE-009: node #115 owned-db open cache budget

- Component ID: `storage`
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes).
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
  The sibling open in RE-015 is context, not a copied implementation.
- Claim status: byte, relocation, and FDE observations, plus an independent
  Rust model of the cache-budget arithmetic and byte-key descent. Setter
  bodies, the open callee, and persistent layout remain unresolved.
- Scope included: unwind extent `0x4524660..0x4524adb` (1,147 bytes), its one
  direct caller `0x37bf00c`, the `db_home` guard call, and the option-slot
  immediates. Scope excluded: RocksDB field stores, snapshot versioning,
  restart, and every indirect caller. No storage gate is requested.

## Question

After a byte-key hit, what cache-size argument and fixed option immediates
does the `owned_db_home.rs` / `rocks_db.rs` body pass, and how does that
default differ from the open already mapped at `0x57c6530`?

## Reproduce

From the repository root, with the authenticated node #115 image and Rust
1.95.0. The capture is not executed.

```sh
python3 tools/owned_db_open_budget_115.py
python3 -m unittest tests.test_owned_db_open_budget_115
cargo test --offline --locked --manifest-path src/node115-owned-db-open/Cargo.toml
```

Addresses below are linked ELF virtual addresses. The FDE end is exclusive.
`records.json` is the tool's record for this image.

## Evidence

The FDE at `0x12aa484` covers `0x4524660` for `0x47b` bytes. Five `int3`
bytes sit outside that extent, before the next unwind start `0x4524ae0`.
The body digest is
`dc1e605f41e2852c1abf20beae609aadff947c84de7f227e46481758a04760bf`.

One direct `e8` call reaches the body, from `0x37bf00c` in
`0x37befd0`. That caller loads the byte at its first argument `+0x10`.
Byte 3 skips the call. Otherwise that byte is the lookup key, and the
qword pair at `*(*(first argument + 8))` is the flag and the size value.

| Check | Bytes | Result |
| --- | --- | --- |
| Root | context `+0x18` | null jumps to the missing-key literal |
| Count / keys / children / value | `+0x62` u16, `[node+0x65+index]`, `[node+0x70+8*index]`, `[node+8+8*index]` | same unsigned byte scan as the db-hub lookup; a hit does not spend height |
| Height | context `+0x20` | `sub $1` / `jb` misses before a child load |
| Hit | `lock incq` on the selected pointer | `jle` reaches `ud2` |
| Guard | call `0x44699c0` | the next instruction does not test `rax`; its failure LEA targets `$db_home contains db_bundle in path: ` |
| Flag | `and $1` | only the low bit is read |
| Default | `mov $0x800, %edi`, then `shl $20` | `0x800<<20` = 2 GiB when the bit is clear |
| Custom | value `<< 10`, then `<< 20`, or `mov $-1` | `value<<30` below `2^34`; `u64::MAX` at and above that boundary (`>> 54` or the post-shift `>> 44` test) |
| Block size | `mov $0x4000, %esi` to slot `0x64eab40` → `0x5d34c40` | 16 KiB immediate in this body |
| Flag / companion | `1` to `0x5d34c50`, `0x8000000` to `0x5d34c60` | immediates at this call site |
| Open | selected `+0x18` / `+0x20` passed to `0x3d5ed10` | those qwords are not re-decoded here |
| Success word | `cmp` with 0, `jo` | only `0x8000000000000000` takes the unwrap literal at `rocks_db.rs:58:49` |
| Publish | selected pointer stored at output `+0x50` | the returned register is the output pointer |

A null block-options object panics at vendored `db_options.rs:650:9` with
`Could not create RocksDB block based options`. A null options object panics
at `db_options.rs:3065:13` with `Could not create RocksDB options`. A null
size-builder result panics at `db_options.rs:56:86`. A missing key panics
with `no entry found for key` at `owned_db_home.rs:72:37`.

The sibling site `0x57c661b` is `mov $0x4000, %edi` in the same shift shape.
That is the 16 GiB default already recorded for `0x57c6530`. This body's
default immediate is `0x800`, so the two opens are not the same policy.

## Implementation and comparison

`src/node115-owned-db-open` is dependency-free Rust for `cache_budget`,
the error-niche word, and `lookup`. It has no Cargo dependencies beyond
its own manifest. The tests cover a clear flag with a huge value, the
`2^34` boundary, duplicate keys, height zero, and a null child. They do
not execute node #115.

No byte window is registered. There is no raw-equal or normalized body
count. Helper stores inside the relocated setters, the 0x50-byte open
image, and allocator failure are not reconstructed.

## Results and limitations

The checked record reports one 1,147-byte body and one direct caller.
Storage gates stay false: this is not a key/value schema, a snapshot
version, or a database open. The next question is what `0x3d5ed10` writes
in the success image, and which bytes the selected object's `+0x18`/`+0x20`
pair actually address.
