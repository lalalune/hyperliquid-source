# Node94 pointer arithmetic return pair

This independent safe `no_std` library reconstructs the complete
`[0x50fa260,0x50fa2b2)` leaf from an immutable numeric memory image.
It returns full RAX/RDX in `Registers` and introduces checked
`AccessError` refusals for invalid reached spans.

```rust
pub fn select(
    image: &[u8], image_base: u64, object: u64,
) -> Result<Registers, AccessError>;
```

Only primary byte 1 selects the stored pair. Every other value selects
the computed path, with an extra subtraction of eight only when its
secondary byte is zero. Field addresses and result arithmetic wrap at
64 bits. The selected path alone determines which fields are required;
the object address itself need not be mapped. Returned numeric values
are not dereferenced. The library allocates nothing and forbids unsafe
code.

The [full proof](../../research/work-items/RE-004-pointer-arithmetic-pair-rust-94/PROOF.md)
states the memory/ABI limits, exact read order, branch and relocation
closure, and all-u64 arithmetic argument. Qualification uses the actual
pinned aarch64-apple-darwin rustc 1.94.1 executable:

```sh
python3 -B research/work-items/RE-004-pointer-arithmetic-pair-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/pointer-arithmetic-pair-rust/replay
```

Use a fresh output directory. The recipe builds opt0/opt3 with overflow
checks enabled and warnings denied, plus repeated artifacts and actual
compiled wrong implementations. No Cargo workspace or dependency
resolution is needed. Only newly authored host programs execute.

The input-only std client consumes 1,042-byte records: little-endian
u64 image base, u64 object address, u16 admitted length 0..1024, and
1,024 backing bytes. Its 17-byte output is a status byte plus full u64
RAX and RDX. Tags 1..5 denote ImageRange, PrimaryFlag, StoredPair,
SecondaryFlag and ComputedWords, with zero placeholders on refusal.
Malformed records are rejected before output. Raw command streams
are retained losslessly in one compressed archive.
