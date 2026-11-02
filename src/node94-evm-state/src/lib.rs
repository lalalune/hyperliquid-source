//! Offline reconstruction of the proven node #94 HyperEVM persistent-state paths.
//!
//! This crate deliberately does not claim to be RocksDB, a state-root implementation,
//! or a complete snapshot codec. See the crate README for the evidence boundary.

mod account;
mod error;
mod key;
mod msgpack;
mod types;

pub use account::{decode_account, encode_account};
pub use error::{DecodeError, EncodeError, OfflineError, StoreError};
pub use key::{decode_key, decode_key_for_table, encode_key};
pub use types::{
    AccountAddress, AccountRecord, CodeHash, Eip7702Code, JumpTable, RawStateRecord,
    SerializedDatabaseKey, SerializedValue, StateKey, StateTable, StorageSlot, StorageValue,
    StoredCode,
};
