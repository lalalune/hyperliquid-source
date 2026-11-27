//! Independently authored Rust reconstruction of Hyperliquid node #115
//! `z_forks/bincode-fork` (target SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//!
//! Integrates the core bincode-fork codec (covering all four observed source paths:
//! `lib.rs`, `de/decoder.rs`, `de/impls.rs`, `enc/write.rs`) alongside re-exports
//! of the verified node #115 serialization micro-crates.

pub mod config;
pub mod de;
pub mod enc;
pub mod error;

/// Re-exports of verified node #115 serialization micro-crates for cross-validation
/// and downstream integration.
pub mod wire_compat {
    pub use node115_attachment_reader as attachment_reader;
    pub use node115_bulk_record_decoder as bulk_record_decoder;
    pub use node115_field1_5_varint_reader as field1_5_varint_reader;
    pub use node115_gossip_address_vector as gossip_address_vector;
    pub use node115_signed_scalar as signed_scalar;
    pub use node115_tcp_bincode_error as tcp_bincode_error;
    pub use node115_u32_varint as u32_varint;
    pub use node115_u64_reader_state as u64_reader_state;
    pub use node115_varint_buffer_writer as varint_buffer_writer;
}

pub use config::{Configuration, Endian, IntEncoding, Limit, legacy, standard};
pub use de::{Decode, DecoderImpl, IoReader, MAX_PREALLOCATION_SIZE, Reader, SliceReader};
pub use enc::{
    ByteVec, Encode, EncoderImpl, IoWriter, SizeWriter, SliceWriter, VecWriter, Writer,
};
pub use error::{AllowedEnumVariants, DecodeError, EncodeError, IntegerType};

/// Encode `val` into a newly allocated `Vec<u8>`.
pub fn encode_to_vec<E: Encode>(val: E, config: Configuration) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = EncoderImpl::new(VecWriter::new(), config);
    val.encode(&mut encoder)?;
    Ok(encoder.into_writer().into_inner())
}

/// Encode `val` into `dst`, returning the number of bytes written.
pub fn encode_into_slice<E: Encode>(
    val: E,
    dst: &mut [u8],
    config: Configuration,
) -> Result<usize, EncodeError> {
    let mut encoder = EncoderImpl::new(SliceWriter::new(dst), config);
    val.encode(&mut encoder)?;
    Ok(encoder.into_writer().bytes_written())
}

/// Compute the encoded byte length of `val` using `SizeWriter`
/// (`z_forks/bincode-fork/src/enc/write.rs:78`).
pub fn encode_size<E: Encode>(val: E, config: Configuration) -> Result<u64, EncodeError> {
    let mut encoder = EncoderImpl::new(SizeWriter::new(), config);
    val.encode(&mut encoder)?;
    Ok(encoder.into_writer().bytes_written)
}

/// Decode `D` from `slice`, returning `(value, bytes_consumed)`.
///
/// Matches `z_forks/bincode-fork/src/lib.rs:171:22`, which computes
/// `slice.len() - decoder.reader().remaining().len()`.
pub fn decode_from_slice<D: Decode>(
    slice: &[u8],
    config: Configuration,
) -> Result<(D, usize), DecodeError> {
    let mut decoder = DecoderImpl::new(SliceReader::new(slice), config);
    let val = D::decode(&mut decoder)?;
    let bytes_read = slice
        .len()
        .checked_sub(decoder.reader().remaining().len())
        .expect("bincode-fork::lib: slice cursor underflow");
    Ok((val, bytes_read))
}
