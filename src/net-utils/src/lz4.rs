//! Size-prefixed LZ4 block compressor and decompressor composed from the verified
//! node #115 LZ4 micro-crates (`dictionary-kernel`, `match-extension`,
//! `match-sequence`, `literal-encoder`, and `lz4-decode`).

use node115_lz4_decode::{self as decoder, DecodeError};
use node115_lz4_dictionary_kernel::{Verdict, large_probe, small_probe};
use node115_lz4_literal_encoder as literal_encoder;
use node115_lz4_match_extension as match_extension;
use node115_lz4_match_sequence as match_sequence;
use node115_tcp_compression_plan::{Codec, Plan, plan as compression_plan};

/// Errors produced during LZ4 compression or decompression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lz4Error {
    InputTooLarge,
    SinkOverflow,
    Decode(DecodeError),
}

impl core::fmt::Display for Lz4Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InputTooLarge => write!(f, "lz4 input exceeds u32 length"),
            Self::SinkOverflow => write!(f, "lz4 compression sink overflow"),
            Self::Decode(e) => write!(f, "decompress_lz4 failure: {e:?}"),
        }
    }
}

impl std::error::Error for Lz4Error {}

/// Maximum worst-case LZ4 block size plus 4-byte LE uncompressed size prefix.
pub fn max_compressed_len(input_len: usize) -> Option<usize> {
    let overhead = input_len / 255 + 16;
    input_len.checked_add(overhead)?.checked_add(4)
}

/// Compress `input` into a 4-byte little-endian uncompressed-length prefix followed
/// by an LZ4 block, using the exact node #115 dictionary/extension/sequence/literal
/// micro-crates (`SmallTable` for `input.len() < 65535`, `LargeTable` otherwise).
pub fn compress_prepend_size(input: &[u8]) -> Result<Vec<u8>, Lz4Error> {
    let raw_len = u32::try_from(input.len()).map_err(|_| Lz4Error::InputTooLarge)?;
    let cap = max_compressed_len(input.len()).ok_or(Lz4Error::InputTooLarge)?;
    let mut out = vec![0u8; cap];
    out[..4].copy_from_slice(&raw_len.to_le_bytes());

    let mut used = 4usize;
    if input.len() < 12 {
        literal_encoder::encode(input, 0, input.len(), &mut out, &mut used)
            .map_err(|_| Lz4Error::SinkOverflow)?;
        out.truncate(used);
        return Ok(out);
    }

    let use_small = input.len() < 65_535;
    if use_small {
        let mut table = [0u16; 4096];
        compress_loop_small(input, &mut table, &mut out, &mut used)?;
    } else {
        let mut table = [0u32; 4096];
        compress_loop_large(input, &mut table, &mut out, &mut used)?;
    }

    out.truncate(used);
    Ok(out)
}

fn compress_loop_small(
    input: &[u8],
    table: &mut [u16; 4096],
    sink: &mut [u8],
    used: &mut usize,
) -> Result<(), Lz4Error> {
    let limit = input.len() - 12;
    let mut anchor = 0usize;
    let mut pos = 0usize;

    // Seed position 0 without matching against itself (distance 0 is invalid in LZ4).
    let _ = small_probe(table, input, 0, 0);
    pos += 1;

    while pos <= limit {
        let probe = small_probe(table, input, pos, 0).map_err(|_| Lz4Error::SinkOverflow)?;
        if let Verdict::Match {
            candidate,
            distance,
        } = probe.verdict
            && distance > 0
            && distance <= u64::from(u16::MAX)
        {
            let mut cursor = pos + 4;
            let extra = match_extension::extend(input, input, &mut cursor, candidate + 4)
                .map_err(|_| Lz4Error::SinkOverflow)?;
            match_sequence::emit(
                &input[anchor..pos],
                extra as u64,
                distance as u16,
                sink,
                used,
            )
            .map_err(|_| Lz4Error::SinkOverflow)?;
            anchor = cursor;
            pos = cursor;
            continue;
        }
        pos += 1;
    }

    literal_encoder::encode(input, anchor, input.len(), sink, used)
        .map_err(|_| Lz4Error::SinkOverflow)
}

fn compress_loop_large(
    input: &[u8],
    table: &mut [u32; 4096],
    sink: &mut [u8],
    used: &mut usize,
) -> Result<(), Lz4Error> {
    let limit = input.len() - 12;
    let mut anchor = 0usize;
    let mut pos = 0usize;

    let _ = large_probe(table, input, 0, 0);
    pos += 1;

    while pos <= limit {
        let probe = large_probe(table, input, pos, 0).map_err(|_| Lz4Error::SinkOverflow)?;
        if let Verdict::Match {
            candidate,
            distance,
        } = probe.verdict
            && distance > 0
            && distance <= u64::from(u16::MAX)
        {
            let mut cursor = pos + 4;
            let extra = match_extension::extend(input, input, &mut cursor, candidate + 4)
                .map_err(|_| Lz4Error::SinkOverflow)?;
            match_sequence::emit(
                &input[anchor..pos],
                extra as u64,
                distance as u16,
                sink,
                used,
            )
            .map_err(|_| Lz4Error::SinkOverflow)?;
            anchor = cursor;
            pos = cursor;
            continue;
        }
        pos += 1;
    }

    literal_encoder::encode(input, anchor, input.len(), sink, used)
        .map_err(|_| Lz4Error::SinkOverflow)
}

/// Decompress a size-prefixed LZ4 block enforcing `max_output_bytes`.
pub fn decompress_size_prepended(input: &[u8], max_output_bytes: u64) -> Result<Vec<u8>, Lz4Error> {
    decoder::decode(input, max_output_bytes).map_err(Lz4Error::Decode)
}

/// Decide whether `input_len` on `port` should be LZ4-compressed according to
/// node #115 `node115-tcp-compression-plan` (`input_len < 1025` or port `3998`/`3999` => raw).
pub fn should_compress_for_port(input_len: usize, port: u16) -> Option<Codec> {
    match compression_plan(input_len as u64, u32::from(port)) {
        Ok(Plan::Compress(cp)) => Some(cp.codec()),
        _ => None,
    }
}
