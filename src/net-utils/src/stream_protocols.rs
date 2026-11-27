//! Binary-backed stream protocol wire codecs recovered from node #115:
//! - `EvmKvsMsg` (`0x26ff830..0x270000c`, `0x2cd7660`, port 3998 uncompressed)
//! - `AbciStreamGreeting` (`0x5821aa0..0x5821f27`, `0x2ceaf00`, port 3999 uncompressed)
//! - `GreetingHash` (`0x582b520..0x582bce8`, `0x2ce1dc0`)

use bincode_fork::{
    AllowedEnumVariants, ByteVec, Decode, DecodeError, DecoderImpl, Encode, EncodeError,
    EncoderImpl, Reader, Writer,
};

/// 65-byte ECDSA signature (`8 * u64` limbs + 1-byte recovery id) matching
/// `node115-greeting-encoder` wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireSignature {
    pub limbs: [u64; 8],
    pub recovery: u8,
}

impl WireSignature {
    pub fn from_bytes(raw: [u8; 65]) -> Self {
        let mut limbs = [0u64; 8];
        for (i, chunk) in raw[..64].chunks_exact(8).enumerate() {
            limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Self {
            limbs,
            recovery: raw[64],
        }
    }

    pub fn to_bytes(self) -> [u8; 65] {
        let mut out = [0u8; 65];
        for (i, word) in self.limbs.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        out[64] = self.recovery;
        out
    }
}

impl Encode for WireSignature {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        for &w in &self.limbs {
            encoder.write_u64(w)?;
        }
        encoder.write_u8(self.recovery)
    }
}

impl Decode for WireSignature {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let mut limbs = [0u64; 8];
        for slot in &mut limbs {
            *slot = decoder.read_u64()?;
        }
        let recovery = decoder.read_u8()?;
        Ok(Self { limbs, recovery })
    }
}

/// 2048-byte fixed block record matching `node115-bulk-record-decoder` (`0x5968840`)
/// and `node115-greeting-encoder::FixedPart`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GreetingFixedPart {
    pub field0: u64,
    pub field1: u64,
    pub bytes: [u8; 2048],
}

impl Encode for GreetingFixedPart {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u64(self.field0)?;
        encoder.write_u64(self.field1)?;
        encoder.write_bytes(&self.bytes)
    }
}

impl Decode for GreetingFixedPart {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let field0 = decoder.read_u64()?;
        let field1 = decoder.read_u64()?;
        decoder.claim_bytes_read(2048)?;
        let mut bytes = [0u8; 2048];
        decoder.reader_mut().read(&mut bytes)?;
        Ok(Self {
            field0,
            field1,
            bytes,
        })
    }
}

/// Inner greeting hash payload decoded at `0x582b520..0x582bce8` / `0x2ce1dc0..0x2ce2a32`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GreetingHash {
    /// Variant 0: hash pair with signature lists.
    Signatures {
        first: [u8; 32],
        left: Vec<WireSignature>,
        right: Vec<WireSignature>,
        last: [u8; 32],
    },
    /// Variant 1: hash pair with `(address[20], signature)` entry maps.
    Maps {
        first: [u8; 32],
        left: Vec<([u8; 20], WireSignature)>,
        right: Vec<([u8; 20], WireSignature)>,
        last: [u8; 32],
    },
    /// Variant 2: three fixed 2048-byte records.
    Fixed(Box<[GreetingFixedPart; 3]>),
}

static GREETING_HASH_VARIANTS: AllowedEnumVariants = AllowedEnumVariants::Range { min: 0, max: 2 };

impl Encode for GreetingHash {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match self {
            Self::Signatures {
                first,
                left,
                right,
                last,
            } => {
                encoder.write_u32(0)?;
                encoder.write_bytes(first)?;
                left.encode(encoder)?;
                right.encode(encoder)?;
                encoder.write_bytes(last)
            }
            Self::Maps {
                first,
                left,
                right,
                last,
            } => {
                encoder.write_u32(1)?;
                encoder.write_bytes(first)?;
                encoder.write_usize(left.len())?;
                for (addr, sig) in left {
                    encoder.write_bytes(addr)?;
                    sig.encode(encoder)?;
                }
                encoder.write_usize(right.len())?;
                for (addr, sig) in right {
                    encoder.write_bytes(addr)?;
                    sig.encode(encoder)?;
                }
                encoder.write_bytes(last)
            }
            Self::Fixed(parts) => {
                encoder.write_u32(2)?;
                for part in parts.iter() {
                    part.encode(encoder)?;
                }
                Ok(())
            }
        }
    }
}

impl Decode for GreetingHash {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => {
                let first = read_fixed32(decoder)?;
                let left = Vec::<WireSignature>::decode(decoder)?;
                let right = Vec::<WireSignature>::decode(decoder)?;
                let last = read_fixed32(decoder)?;
                Ok(Self::Signatures {
                    first,
                    left,
                    right,
                    last,
                })
            }
            1 => {
                let first = read_fixed32(decoder)?;
                let left = decode_sig_map(decoder)?;
                let right = decode_sig_map(decoder)?;
                let last = read_fixed32(decoder)?;
                Ok(Self::Maps {
                    first,
                    left,
                    right,
                    last,
                })
            }
            2 => {
                let p0 = GreetingFixedPart::decode(decoder)?;
                let p1 = GreetingFixedPart::decode(decoder)?;
                let p2 = GreetingFixedPart::decode(decoder)?;
                Ok(Self::Fixed(Box::new([p0, p1, p2])))
            }
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "GreetingHash",
                allowed: &GREETING_HASH_VARIANTS,
                found: other,
            }),
        }
    }
}

fn read_fixed32<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<[u8; 32], DecodeError> {
    decoder.claim_bytes_read(32)?;
    let mut out = [0u8; 32];
    decoder.reader_mut().read(&mut out)?;
    Ok(out)
}

fn decode_sig_map<R: Reader>(
    decoder: &mut DecoderImpl<R>,
) -> Result<Vec<([u8; 20], WireSignature)>, DecodeError> {
    let len = decoder.read_usize()?;
    decoder.claim_container_read::<([u8; 20], WireSignature)>(len)?;
    let elem_size = core::mem::size_of::<([u8; 20], WireSignature)>();
    let mut entries = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        decoder.unclaim_bytes_read(elem_size);
        decoder.claim_bytes_read(20)?;
        let mut addr = [0u8; 20];
        decoder.reader_mut().read(&mut addr)?;
        let sig = WireSignature::decode(decoder)?;
        entries.push((addr, sig));
    }
    Ok(entries)
}

/// Complete 6-variant `AbciStreamGreeting` wire enum recovered from
/// `0x5821aa0..0x5821f27` (jump table `0x935bfc`) and `node115-greeting-encoder`.
///
/// Variant 0 decodes `blob` via `bincode-fork`'s `ByteVec` path (enforcing
/// `DecodeError::InvalidBytesLength` at `0x5821b64..0x5821b75`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbciStreamGreeting {
    Kind0 {
        blob: ByteVec,
        height: u64,
        hash: Box<GreetingHash>,
    },
    Kind1 {
        field0: u64,
        field1: u64,
        field2: u64,
    },
    Kind2,
    Kind3,
    Kind4,
    Kind5,
}

static ABCI_GREETING_VARIANTS: AllowedEnumVariants = AllowedEnumVariants::Range { min: 0, max: 5 };

impl Encode for AbciStreamGreeting {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match self {
            Self::Kind0 { blob, height, hash } => {
                encoder.write_u32(0)?;
                blob.encode(encoder)?;
                encoder.write_u64(*height)?;
                hash.encode(encoder)
            }
            Self::Kind1 {
                field0,
                field1,
                field2,
            } => {
                encoder.write_u32(1)?;
                encoder.write_u64(*field0)?;
                encoder.write_u64(*field1)?;
                encoder.write_u64(*field2)
            }
            Self::Kind2 => encoder.write_u32(2),
            Self::Kind3 => encoder.write_u32(3),
            Self::Kind4 => encoder.write_u32(4),
            Self::Kind5 => encoder.write_u32(5),
        }
    }
}

impl Decode for AbciStreamGreeting {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => {
                let blob = ByteVec::decode(decoder)?;
                let height = decoder.read_u64()?;
                let hash = Box::new(GreetingHash::decode(decoder)?);
                Ok(Self::Kind0 { blob, height, hash })
            }
            1 => {
                let field0 = decoder.read_u64()?;
                let field1 = decoder.read_u64()?;
                let field2 = decoder.read_u64()?;
                Ok(Self::Kind1 {
                    field0,
                    field1,
                    field2,
                })
            }
            2 => Ok(Self::Kind2),
            3 => Ok(Self::Kind3),
            4 => Ok(Self::Kind4),
            5 => Ok(Self::Kind5),
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "AbciStreamGreeting",
                allowed: &ABCI_GREETING_VARIANTS,
                found: other,
            }),
        }
    }
}

/// Complete 2-variant `EvmKvsMsg` wire enum recovered from node #115
/// `0x26ff830..0x270000c` (`node/src/evm_kvs.rs`, port 3998 uncompressed):
/// - Variant 0 (`0x26ffa1b` -> `0x232c140` + `0x2cd7660`): `Batch(Vec<(key, val)>)`
/// - Variant 1 (`0x26ff93a`): `Done` (unit end-of-stream marker)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvmKvsMsg {
    Batch(Vec<(ByteVec, ByteVec)>),
    Done,
}

static EVM_KVS_VARIANTS: AllowedEnumVariants = AllowedEnumVariants::Range { min: 0, max: 1 };

impl Encode for EvmKvsMsg {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        match self {
            Self::Batch(entries) => {
                encoder.write_u32(0)?;
                entries.encode(encoder)
            }
            Self::Done => encoder.write_u32(1),
        }
    }
}

impl Decode for EvmKvsMsg {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => Ok(Self::Batch(Vec::<(ByteVec, ByteVec)>::decode(decoder)?)),
            1 => Ok(Self::Done),
            other => Err(DecodeError::UnexpectedVariant {
                type_name: "EvmKvsMsg",
                allowed: &EVM_KVS_VARIANTS,
                found: other,
            }),
        }
    }
}
