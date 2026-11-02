//! Codec and optional asynchronous I/O for the verified node #94 frame format.
//!
//! The `stream` feature accepts caller-owned Tokio I/O; `timed-stream` adds the
//! qualified header and per-chunk deadlines. Neither feature selects peers,
//! opens sockets, or implements a complete node protocol.

#![forbid(unsafe_code)]

#[cfg(feature = "checkpoint-hash")]
pub mod checkpoint_hash;
mod compression;
#[cfg(feature = "timed-stream")]
pub mod deadlines;
mod decoder;
mod encoder;
#[cfg(feature = "timed-stream")]
pub mod evm_kvs;
#[cfg(feature = "timed-stream")]
pub mod greeting;
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
