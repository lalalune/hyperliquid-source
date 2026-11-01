# Node94 self-guarded field chain

This safe `no_std` library reconstructs `[0x5172e50,0x5172e77)` for node94
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
`load(image,image_base,object)` projects complete RAX and RDX.

It reads P from the wrapped address object+8 and G from P. If G equals P
in all 64 bits, both results are all ones. Otherwise it reads Q from P+8,
R from Q+16, and V from R+0xcb8; both results are V. These are qword loads
with independently wrapped numeric addresses. The self branch skips all three
later reads. A zero P still requires its guard read and can take the chain.
A chain value of all ones remains a successful value.

The immutable slice represents one nonwrapping numeric address interval.
Only reached complete eight-byte spans are required; partial and exact data
aliases are admitted. Numeric addresses never become Rust pointers. `None`
refuses invalid images or missing reached spans and is distinct from the
all-ones result. The library has no fixture-size cap and performs no writes.

Original correspondence assumes stable ordinary memory and normally completing
control/reads. Native ABI, faults, flags, MMIO, races, control-data aliases,
handlers and original compiled-byte identity are not projected. No original
source type or meaning of the default value is inferred.

The [proof](../../research/work-items/RE-004-self-guarded-chain-rust-94/PROOF.md)
and [packet](../../research/work-items/RE-004-self-guarded-chain-rust-94/README.md)
contain exact full-body/FDE/caller evidence and independently frozen expectations.
The input-only client uses 152-byte records (three u64 descriptors plus a
128-byte image) and emits status/RAX/RDX as three u64 words; it receives no
expected outputs or captured instructions.
