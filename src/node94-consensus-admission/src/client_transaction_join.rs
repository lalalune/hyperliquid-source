//! Conditional client transaction join recovered from node94 `0x4548050`.
//!
//! This operation preserves opaque block/proof ownership and raw time. It does
//! not authenticate blocks, hash transaction bytes, or check supplied rows
//! against the requested hashes. Native correspondence requires the stable
//! views, allocation and ownership premises in `RE-008-client-transaction-join-94`.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::TransactionHash;

/// A requested hash and shared transaction bytes. Identity is the Arc identity.
#[derive(Clone, Debug)]
pub struct JoinedTransaction {
    pub hash: TransactionHash,
    pub bytes: Arc<Vec<u8>>,
}

/// Owned input; `B` preserves the entire opaque block and any proof payload.
#[derive(Debug)]
pub struct ClientJoinInput<B> {
    pub block: Arc<B>,
    pub rows: Option<Arc<Vec<JoinedTransaction>>>,
    pub time: [u8; 12],
}

/// Successful join, preserving the input block and raw time.
#[derive(Debug)]
pub struct JoinedClientBlock<B> {
    pub block: Arc<B>,
    pub rows: Arc<Vec<JoinedTransaction>>,
    pub time: [u8; 12],
}

/// Only `MissingTransaction` corresponds to the ordinary native error tag 0x1c.
/// View, count and reservation refusals are explicit safe host policies.
#[derive(Debug, Eq, PartialEq)]
pub enum JoinError<E> {
    MissingTransaction(TransactionHash),
    HashView(E),
    MapView(E),
    RowCountLimit,
    Reservation,
}

/// Admit the native 40-byte row span and the host's signed addressable span.
///
/// This is used by actual join admission. It does not describe Rust row layout,
/// actual Vec capacity, or allocator allocation size. Actual layout/reservation
/// is checked separately by `Vec::try_reserve_exact`.
pub fn checked_row_bytes(count: u64) -> Option<usize> {
    let bytes = count.checked_mul(40)?;
    if bytes > i64::MAX as u64 {
        return None;
    }
    let bytes = usize::try_from(bytes).ok()?;
    if bytes > isize::MAX as usize {
        return None;
    }
    Some(bytes)
}

/// Join in request order with actual ordered-map lookup and Arc sharing.
///
/// Supplied rows return unchanged without invoking either view provider. Absent
/// empty hashes invoke only the hash provider. For a nonempty list, the first
/// missing hash discards the successful prefix and consumes the input block.
/// Providers are safe adapters for deferred checked access, not native callbacks.
/// Their successful values must agree with the corresponding native views when
/// applying the conditional native contract. Arbitrary provider/payload Drop
/// effects and allocation failure of the final Arc are outside that contract.
pub fn join_transactions<'a, B, E, H, M>(
    input: ClientJoinInput<B>,
    hash_view: H,
    map_view: M,
) -> Result<JoinedClientBlock<B>, JoinError<E>>
where
    H: FnOnce() -> Result<&'a [TransactionHash], E>,
    M: FnOnce() -> Result<&'a BTreeMap<TransactionHash, Arc<Vec<u8>>>, E>,
{
    let ClientJoinInput { block, rows, time } = input;
    if let Some(rows) = rows {
        return Ok(JoinedClientBlock { block, rows, time });
    }

    let hashes = hash_view().map_err(JoinError::HashView)?;
    let count = u64::try_from(hashes.len()).map_err(|_| JoinError::RowCountLimit)?;
    checked_row_bytes(count).ok_or(JoinError::RowCountLimit)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(hashes.len())
        .map_err(|_| JoinError::Reservation)?;
    if !hashes.is_empty() {
        let map = map_view().map_err(JoinError::MapView)?;
        for hash in hashes {
            let Some(bytes) = map.get(hash) else {
                drop(rows);
                drop(block);
                return Err(JoinError::MissingTransaction(*hash));
            };
            rows.push(JoinedTransaction {
                hash: *hash,
                bytes: Arc::clone(bytes),
            });
        }
    }
    Ok(JoinedClientBlock {
        block,
        rows: Arc::new(rows),
        time,
    })
}
