#![no_std]
//! Bounded composition of existing node 115 response decoder components.
//! This is a logical prefix API, not a native ABI or complete protocol.
extern crate alloc;
use alloc::vec::Vec;
use node115_client_block_success as client_success;
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
    ClientBlocks(Vec<client_success::Client>),
    Variant2(Option<outer::Record>),
    /// Limited decoding reached success, but payload metering is unresolved.
    ResultSuccessBoundary,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Outer(outer::Error),
    Addresses(address_vector::Error),
    ResultTag(scalar::ReadError),
    InvalidResultTag(u32),
    ClientBlocksError(client_error::Error),
    ClientBlocksSuccess(client_success::Error),
}
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Response, Error>,
    pub remaining: &'a [u8],
    pub charged: u64,
}

/// Decode selected response prefixes, preserving child cursor and charge.
/// Raw outer tag 0 enters a nested Result; tag 1 is the address vector.
/// In unlimited mode, nested success uses the separately qualified structural
/// ClientBlocks parser. In limited mode, that payload remains an explicit
/// boundary because its nested charge behavior has not been established.
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
                0 if limit.is_none() => {
                    let value = client_success::decode_payload_prefix(remaining);
                    Outcome {
                        result: value
                            .result
                            .map(Response::ClientBlocks)
                            .map_err(Error::ClientBlocksSuccess),
                        remaining: value.remaining,
                        charged,
                    }
                }
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

/// Result of opt-in success composition, preserving the original parent enums.
#[derive(Debug, PartialEq, Eq)]
pub enum ComposedResponse {
    Parent(Response),
    ClientBlocksSuccess(Vec<node115_client_block_success::Client>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ComposedError {
    Parent(Error),
    ClientBlocksSuccess(node115_client_block_success::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ComposedOutcome<'a> {
    pub result: Result<ComposedResponse, ComposedError>,
    pub remaining: &'a [u8],
    pub charged: u64,
}

/// Compose the selected success child; `decode_prefix` keeps its old boundary.
pub fn decode_prefix_with_success(
    input: &[u8],
    limit: Option<u64>,
    charged: u64,
) -> ComposedOutcome<'_> {
    let parent = decode_prefix(input, limit, charged);
    if matches!(parent.result, Ok(Response::ResultSuccessBoundary)) {
        let child = node115_client_block_success::decode_payload_prefix_metered(
            parent.remaining,
            limit,
            parent.charged,
        );
        ComposedOutcome {
            result: child
                .result
                .map(ComposedResponse::ClientBlocksSuccess)
                .map_err(ComposedError::ClientBlocksSuccess),
            remaining: child.remaining,
            charged: child.charged,
        }
    } else {
        ComposedOutcome {
            result: parent
                .result
                .map(ComposedResponse::Parent)
                .map_err(ComposedError::Parent),
            remaining: parent.remaining,
            charged: parent.charged,
        }
    }
}
