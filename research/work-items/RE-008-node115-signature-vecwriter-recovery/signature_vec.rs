// Compiled beside the pinned baseline to reuse its encoder ABI and varint stub.
// The alternate inline field is a compile-time negative control.
#[repr(C)]
pub struct SignatureView<'a> {
    pub r: [u64; 4],
    pub s: [u64; 4],
    #[cfg(not(inline_recovery))]
    pub recovery: &'a u8,
    #[cfg(inline_recovery)]
    pub recovery: u8,
    #[cfg(inline_recovery)]
    pub lifetime: core::marker::PhantomData<&'a u8>,
}

#[inline(never)]
pub fn encode_signature_view(
    signature: &SignatureView<'_>,
    enc: &mut EncVec,
) -> Result<(), EncodeError> {
    signature.r[0].encode(enc)?;
    signature.r[1].encode(enc)?;
    signature.r[2].encode(enc)?;
    signature.r[3].encode(enc)?;
    signature.s[0].encode(enc)?;
    signature.s[1].encode(enc)?;
    signature.s[2].encode(enc)?;
    signature.s[3].encode(enc)?;
    #[cfg(not(inline_recovery))]
    enc.writer.buf.push(*signature.recovery);
    #[cfg(inline_recovery)]
    enc.writer.buf.push(signature.recovery);
    Ok(())
}
