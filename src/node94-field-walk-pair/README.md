# Node94 field-derived store pair

This safe `no_std` library reconstructs complete entries
`[0x514ab20,0x514ab4a)` and `[0x514ab50,0x514ab64)` for node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It projects full RAX/RDX and every final byte of a supplied memory image.

`apply(member,image,image_base,object,incoming_rdx,output)` has two members:

- `ShiftedDifference` follows the qword at object+0x788, then its field +0x30
  to Q. It subtracts the qwords Q+0xb20 minus Q+0xb18 modulo64, interprets the
  result as signed64, arithmetic-shifts by four, and stores eight bytes at
  output. RAX is 1 and RDX retains Q.
- `SignedField` reads exactly four bytes at incoming_rdx+0x1438, sign-extends
  to 64 bits and stores eight bytes at output. RAX is 1 and RDX preserves
  incoming_rdx. This member never reads object.

Effective addresses wrap modulo64; scalar subtraction wraps before the signed
shift. All reads precede the store, preserving partial and exact data aliases.
The slice describes one nonwrapping numeric address interval. Missing spans
or an overflowing image description return `None` without changing any byte.
These are new safe refusals, not recovered machine-fault results. Numeric
metadata never becomes a Rust pointer. The library has no fixture-size cap.

The correspondence assumes stable ordinary memory and normal control. Native
ABI, faults, MMIO, races, code/control aliases, flags and original compiled-byte
identity remain outside the projection. No source structure or library name
is inferred from the neighboring functions.

The [proof](../../research/work-items/RE-004-field-walk-pair-rust-94/PROOF.md)
covers every u64/u32 value, read/store width, alias and safe refusal. The
[evidence packet](../../research/work-items/RE-004-field-walk-pair-rust-94/README.md)
contains original bytes/FDE closure, frozen independent expectations and
actual native builds. The input-only client takes 176-byte records and emits
152-byte status/RAX/RDX/image records; its 128-byte image capacity is solely a
qualification format, not an original ABI or source-domain limit.
