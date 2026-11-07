#![no_std]
//! Bounded composition of existing node 115 response decoder components.
//! This is a logical prefix API, not a native ABI or complete protocol.
extern crate alloc;
use alloc::vec::Vec;
use node115_client_blocks_error as client_error;
use node115_gossip_response_v2_envelope as outer;
use node115_u32_varint as scalar;

// Reuse the existing MIT source unchanged through a module so both child
// decoders share one byte-identical reader package. Their separate manifests
// otherwise name two different path packages identically in one lockfile.
#[allow(unused_attributes)]
#[path = "../../node115-gossip-address-vector/src/lib.rs"]
pub mod address_vector;
pub use address_vector::Record as AddressRecord;

#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Addresses(Vec<AddressRecord>),
    ClientBlocksError(client_error::Value),
    Variant2(Option<outer::Record>),
    /// The nested success tag was consumed; its payload is not decoded here.
    ResultSuccessBoundary,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Outer(outer::Error),
    Addresses(address_vector::Error),
    ResultTag(scalar::ReadError),
    InvalidResultTag(u32),
    ClientBlocksError(client_error::Error),
}
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Response, Error>,
    pub remaining: &'a [u8],
    pub charged: u64,
}

/// Decode a selected response prefix, preserving cursor and charge on errors.
/// Raw outer tag 0 enters a nested Result; tag 1 is the address vector.
/// The unimplemented nested success payload is an explicit boundary, not a
/// successful complete response; no EOF or native layout is asserted.
pub fn decode_prefix(input: &[u8], limit: Option<u64>, charged: u64) -> Outcome<'_> {
    let result = outer::decode_prefix(input, limit, charged);
    let mut remaining = result.remaining;
    let mut charged = result.charged;
    match result.result {
        Err(e) => Outcome {
            result: Err(Error::Outer(e)),
            remaining,
            charged,
        },
        Ok(outer::Selection::Variant2(value)) => Outcome {
            result: Ok(Response::Variant2(value)),
            remaining,
            charged,
        },
        Ok(outer::Selection::OtherVariant(1)) => {
            let value = address_vector::decode_prefix(remaining, limit, charged);
            Outcome {
                result: value
                    .result
                    .map(Response::Addresses)
                    .map_err(Error::Addresses),
                remaining: value.remaining,
                charged: value.charged,
            }
        }
        Ok(outer::Selection::OtherVariant(0)) => {
            let mode = u32::from(limit.is_some());
            let tag = match scalar::read_u32(&mut remaining, mode, limit.unwrap_or(0), &mut charged)
            {
                Ok(tag) => tag,
                Err(e) => {
                    return Outcome {
                        result: Err(Error::ResultTag(e)),
                        remaining,
                        charged,
                    };
                }
            };
            match tag {
                0 => Outcome {
                    result: Ok(Response::ResultSuccessBoundary),
                    remaining,
                    charged,
                },
                1 => {
                    let value = client_error::decode_prefix(remaining, limit, charged);
                    Outcome {
                        result: value
                            .result
                            .map(Response::ClientBlocksError)
                            .map_err(Error::ClientBlocksError),
                        remaining: value.remaining,
                        charged: value.charged,
                    }
                }
                other => Outcome {
                    result: Err(Error::InvalidResultTag(other)),
                    remaining,
                    charged,
                },
            }
        }
        Ok(outer::Selection::OtherVariant(_)) => unreachable!("outer decoder accepts only 0 and 1"),
    }
}
