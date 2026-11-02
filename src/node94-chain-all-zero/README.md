# Node #94 flag-gated chain predicate

This safe, dependency-free `no_std` component reconstructs the normal-return
value of the complete node #94 leaf `[0x51a5d60,0x51a5da8)`, target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

```rust
pub fn all_zero(image: &[u8], image_base: u64, root_slot: u64)
    -> Result<bool, AccessError>
```

Image byte `j` represents address `image_base+j`; `root_slot` is the original
RDI address. The function loads an object pointer there. Its byte at `+112`
being nonzero returns false immediately. Otherwise its qword at `+72` is a chain
head. Null ends the chain and returns true. A nonzero qword at a node's `+16`
returns false without reading that node's link. A zero field follows the qword
at the node's own address. All actual accesses are little-endian.

The original writes full EAX on every normal return, yielding full RAX 0 or 1.
`u64::from` of the successful bool is this exact value projection; the new Rust
`Result` ABI is not the original calling convention. Effective address additions
wrap as u64, while each actual access must fit the supplied nonwrapping image.
Overlapping input regions are allowed because the image is immutable.

Bounds errors are new safe refusals. `Cycle` means a stable all-zero chain would
repeat forever in the original; it is not an original error return. The library
uses a proved bound on distinct readable qword-start addresses, derived from the
actual image length, without a fixed node limit or heap allocation. Worst-case
cycle detection takes O(image length) iterations, even for a short cycle in a
large image. Terminating paths retain their needed-read order.

The correspondence assumes ordinary mapped readable memory, stable through the
call, unchanged code and normal return/control behavior. Faults, concurrency,
MMIO, external read observations and CPU flags are excluded. Numeric fixture
addresses do not assert actual target mappings. No source type, function purpose,
compiler provenance, original compiled-byte identity or whole-node match is claimed.

The [evidence packet](../../research/work-items/RE-004-chain-all-zero-rust-94/README.md)
retains the full proof, complete body/caller decodes, frozen graph oracle and
exact rustc 1.94.1 opt0/3 recipes. `input_only_driver.rs` supplies real 512-byte
images and emits the result plus the unchanged complete image; it reads no
expected outputs. The library itself has no 512-byte image cap.
