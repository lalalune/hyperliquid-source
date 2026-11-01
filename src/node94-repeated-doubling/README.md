# Raw six-word repeated doubling

Independent MIT `no_std` value reconstruction of complete node94 entries
`0x5656c40`, `0x5656d20`, `0x5656de0`, and `0x5656f00` (594 bytes).
The API covers one prepared step, three steps, the low32 counted loop, and
three steps per block with low-block stores before high-block reads.

For K=2^384, each raw step is `(2X - M*[2X>=M]) mod K`. All X/M bit patterns
are admitted; X=M stays M and M=0 doubles modulo K. The counted entry performs
2^32 steps when the incoming low32 count is zero. A proved 384-step convergence
bound permits bounded acceleration while preserving exact final temporary
registers. This is not a canonical reduction or a recovered cryptographic name.

`apply` operates on one supplied byte image and returns all fifteen general
registers except RSP. Arbitrary unaligned data aliases are supported; pair high
A/M are read after low stores. PreparedStep takes incoming R8..R13 and needs no
mapped A/output span. Code and valid stack/control storage are disjoint from
the image, and M is stable between reads within a block. `None` is a new atomic
image-domain refusal, not an original return/fault. Flags, RSP, concurrency and
original ABI are excluded.

The [evidence packet](../../research/work-items/RE-004-node94-repeated-doubling-rust/README.md)
contains the complete proof, frozen independent expectations, static closure,
new native Rust validation and actual wrong-variant observations. No captured
code or instruction emulator is executed. No existing gate or pin changes.
