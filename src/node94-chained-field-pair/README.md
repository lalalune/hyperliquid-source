# Node94 chained-field accessor pair

`extract(field, image, image_base, object, output)` follows two qword
pointers, reads the selected deep field, stores one qword and returns
full native RAX=1. Signed32 sign-extends a four-byte field; Word64 copies
an eight-byte field. All reads precede the output write, allowing arbitrary
data aliases. Safe refusals preserve every image byte.

The dependency-free safe `no_std` source builds directly with rustc.
This is an abstract-address image API, excluding native ABI and fault
timing. See the [evidence packet](../../research/work-items/RE-004-chained-field-pair-rust-94/README.md)
and [proof](../../research/work-items/RE-004-chained-field-pair-rust-94/PROOF.md)
for the complete domain and reproduction commands.
