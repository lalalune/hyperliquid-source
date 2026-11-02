# Node #94 indexed accumulator

This independently authored, dependency-free safe `no_std` component reconstructs
the complete 44-byte leaf `[0x514ac60, 0x514ac8c)` in node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

```rust
pub fn accumulate(
    image: &mut [u8], image_base: u64,
    selector_slot: u64, addend_address: u64, base_slot: u64,
) -> Result<u64, AccessError>
```

The three address arguments represent entry R8, RCX and RDI. Image byte `j`
represents address `image_base+j`. The function reads the selector pointer and
addend, uses index 13 when the loaded pointer is zero or its signed 32-bit field
at `+32` otherwise, then reads the base pointer. It calculates
`entry = base + 8*index` modulo `2^64`, increments the qword at `entry+176`, adds
the snapshotted addend to the qword at `entry+64`, and returns `entry`.

The return is the full numeric RAX value, **not the index**. The old foundation
packet's prose and tool header incorrectly describe an index return: the LEA
at `0x514ac7b` overwrites RAX with the entry address. The new
[proof and evidence](../../research/work-items/RE-004-indexed-accumulator-rust-94/README.md)
establish the correction without modifying imported/prior evidence.

All effective address arithmetic wraps as u64 before checking whether the
accessed bytes fit the supplied nonwrapping image. The entry address itself is
only returned and used in later address calculations; it need not be mapped.
All input/output aliases within the image are supported. Inputs are read before
the two ordered stores. Both output ranges are checked before mutation, so every
new `AccessError` leaves the complete image unchanged. These refusals are new
safe behavior, not original error returns or fault/partial-store observations.

Correspondence assumes valid ordinary mapped memory and normal target execution,
stable except for this function's writes. Faults, MMIO, concurrent observations,
code/return-stack/control-state aliasing, register flags and the raw SysV ABI
are outside the claim. Arbitrary numeric test images do not assert actual target
virtual-address mappings. No original source type, purpose, caller provenance,
compiler or compiled-byte identity is claimed.

The input-only research driver supplies real 512-byte backing images and emits
the returned value/error tag plus every byte, including bytes outside the admitted
slice. The library has no 512-byte size cap. The packet retains exact rustc 1.94.1
build commands for opt0/3; no Cargo dependency graph or root workspace is invented.
