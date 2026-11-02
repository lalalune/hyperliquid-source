//! Codec and optional asynchronous I/O for the verified node #94 frame format.
//!
//! The `stream` feature accepts caller-owned Tokio I/O. It does not select peers,
//! open sockets, impose timeouts, or implement a complete node protocol.

#![forbid(unsafe_code)]

mod compression;
mod decoder;
mod encoder;
mod header;
mod limits;
#[cfg(feature = "stream")]
pub mod stream;

pub use compression::{
    COMPRESSION_THRESHOLD, CompressionSizeError, HashTableWidth, compressed_allocation_len,
    compressed_output_capacity, compression_size_prefix, hash_table_width, should_compress,
};
pub use decoder::{DecodeError, DecodedFrame, Lz4DecodeError, decode_frame};
pub use encoder::{EncodeError, EncodedFrame, encode_frame};
pub use header::{HEADER_LEN, Header, HeaderError};
pub use limits::{CHUNK_LEN, Chunk, ChunkPlan, FrameLimits, LengthError};
