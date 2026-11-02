use std::collections::BTreeMap;

use crate::{RecordStore, StoreError};

/// Deterministic test fixture. This is not a reconstruction of the target's RocksDB wrapper.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryStore {
    records: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl RecordStore for MemoryStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.records.get(key).cloned())
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.records.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}
