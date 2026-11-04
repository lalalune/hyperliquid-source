# Node115 logical flag/two-word reader

This independently authored no_std component reconstructs the value/error/cursor
relation of linked-VA0x298f160 and0x2a00700, bound to Node115 SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
See research/work-items/RE-005-node115-rlp-flag-pair for complete static evidence,
the frozen predictions, error boundaries, commands and limitations.

Reader owns a safe slice and exposes consumed/remaining bytes. FlagPair returns
a boolean and two unsigned256 values as four little-endian limbs each.
DecodeError exposes only the observed numeric discriminant. Original ABI,
padding, inactive error fields, domain/schema and runtime helper closure are
not reconstructed. Requires a64-bit target for the original size domain.
This is not a complete protocol implementation or a security validation API.
