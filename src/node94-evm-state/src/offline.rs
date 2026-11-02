use crate::{
    AccountAddress, AccountRecord, AccumulatorDelta, CodeHash, DecodeError, LatticeAccumulator,
    OfflineError, RawStateRecord, SerializedDatabaseKey, SerializedValue, StateKey, StorageSlot,
    StoreError, StoredCode, VerifiedEntryBytes, decode_account, decode_key, decode_supported_code,
    encode_account, encode_code, encode_key,
};

pub trait RecordStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StoreError>;
}

/// Supplies the complete entry bytes that the target hashes into its lattice.
///
/// The full preimage format is unresolved in retained evidence, so this is deliberately
/// injected rather than guessed by the crate.
pub trait EntryMaterializer {
    fn materialize(&self, record: &RawStateRecord) -> Result<VerifiedEntryBytes, StoreError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseUpdate {
    Put(RawStateRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedReplacement {
    pub previous: Option<RawStateRecord>,
    pub update: DatabaseUpdate,
    pub accumulator_after: LatticeAccumulator,
    pub delta: AccumulatorDelta,
}

/// Bounded offline read/write operations over a caller-provided backing store.
///
/// This type neither assumes RocksDB nor couples database writes to accumulator acceptance.
/// Callers explicitly choose when to apply a prepared database update and when to publish the
/// returned accumulator state.
pub struct OfflineState<S> {
    store: S,
}

impl<S> OfflineState<S> {
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    #[must_use]
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    #[must_use]
    pub fn account_key(address: AccountAddress) -> SerializedDatabaseKey {
        encode_key(&StateKey::Account(address))
    }

    #[must_use]
    pub fn code_key(hash: CodeHash) -> SerializedDatabaseKey {
        encode_key(&StateKey::ContractCode(hash))
    }

    #[must_use]
    pub fn storage_key(address: AccountAddress, slot: StorageSlot) -> SerializedDatabaseKey {
        encode_key(&StateKey::Storage { address, slot })
    }
}

impl<S: RecordStore> OfflineState<S> {
    pub fn read_account(
        &self,
        address: AccountAddress,
    ) -> Result<Option<AccountRecord>, OfflineError> {
        let key = Self::account_key(address);
        self.store
            .get(key.as_bytes())?
            .map(|bytes| decode_account(&bytes).map_err(OfflineError::from))
            .transpose()
    }

    pub fn read_supported_code(&self, hash: CodeHash) -> Result<Option<StoredCode>, OfflineError> {
        let key = Self::code_key(hash);
        self.store
            .get(key.as_bytes())?
            .map(|bytes| decode_supported_code(&bytes).map_err(OfflineError::from))
            .transpose()
    }

    pub fn write_account(
        &mut self,
        address: AccountAddress,
        account: &AccountRecord,
    ) -> Result<(), OfflineError> {
        let key = Self::account_key(address);
        let value = encode_account(account)?;
        self.store.put(key.as_bytes(), value.as_bytes())?;
        Ok(())
    }

    pub fn write_code(&mut self, hash: CodeHash, code: &StoredCode) -> Result<(), OfflineError> {
        let key = Self::code_key(hash);
        let value = encode_code(code)?;
        self.store.put(key.as_bytes(), value.as_bytes())?;
        Ok(())
    }

    /// Look up the previous value and compute the proven old-remove/new-add accounting order.
    ///
    /// No database write occurs here. This separation is implementation policy because native
    /// transactionality and rollback behavior remain unresolved.
    pub fn prepare_replacement<M: EntryMaterializer>(
        &self,
        accumulator: &LatticeAccumulator,
        replacement: RawStateRecord,
        materializer: &M,
    ) -> Result<PreparedReplacement, OfflineError> {
        let key_kind = decode_key(replacement.key.as_bytes())?;
        ensure_value_matches_key(&key_kind, &replacement.value)?;

        let previous = self
            .store
            .get(replacement.key.as_bytes())?
            .map(|bytes| classify_raw_record(replacement.key.clone(), &key_kind, bytes))
            .transpose()?;
        let old_entry = previous
            .as_ref()
            .map(|record| materializer.materialize(record))
            .transpose()?;
        let new_entry = materializer.materialize(&replacement)?;

        let mut accumulator_after = accumulator.clone();
        let delta = accumulator_after.replace(old_entry.as_ref(), &new_entry);
        Ok(PreparedReplacement {
            previous,
            update: DatabaseUpdate::Put(replacement),
            accumulator_after,
            delta,
        })
    }

    /// Apply only the database portion of a prepared operation.
    ///
    /// Publishing `accumulator_after`, rollback, batching, and atomicity are caller policy.
    pub fn apply_database_update(&mut self, update: &DatabaseUpdate) -> Result<(), StoreError> {
        match update {
            DatabaseUpdate::Put(record) => self
                .store
                .put(record.key.as_bytes(), record.value.as_bytes()),
        }
    }
}

fn ensure_value_matches_key(key: &StateKey, value: &SerializedValue) -> Result<(), DecodeError> {
    let matches = matches!(
        (key, value),
        (StateKey::Account(_), SerializedValue::Account(_))
            | (StateKey::ContractCode(_), SerializedValue::ContractCode(_))
            | (StateKey::Storage { .. }, SerializedValue::Storage(_))
    );
    if matches {
        Ok(())
    } else {
        Err(DecodeError::WrongPrefix {
            expected: key_prefix(key),
            actual: value_prefix(value),
        })
    }
}

fn classify_raw_record(
    key: SerializedDatabaseKey,
    key_kind: &StateKey,
    bytes: Vec<u8>,
) -> Result<RawStateRecord, DecodeError> {
    let value = match key_kind {
        StateKey::Account(_) => SerializedValue::Account(bytes),
        StateKey::ContractCode(_) => SerializedValue::ContractCode(bytes),
        StateKey::Storage { .. } => {
            let actual = bytes.len();
            let bytes = bytes.try_into().map_err(|_| DecodeError::WrongLength {
                context: "stored storage value",
                expected: 32,
                actual,
            })?;
            SerializedValue::Storage(bytes)
        }
    };
    Ok(RawStateRecord { key, value })
}

const fn key_prefix(key: &StateKey) -> [u8; 2] {
    match key {
        StateKey::Account(_) => *b"Ea",
        StateKey::ContractCode(_) => *b"Ec",
        StateKey::Storage { .. } => *b"Es",
    }
}

const fn value_prefix(value: &SerializedValue) -> [u8; 2] {
    match value {
        SerializedValue::Account(_) => *b"Ea",
        SerializedValue::ContractCode(_) => *b"Ec",
        SerializedValue::Storage(_) => *b"Es",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StorageValue, encode_storage_value, test_fixtures::MemoryStore};

    struct KeyValueMaterializer;

    impl EntryMaterializer for KeyValueMaterializer {
        fn materialize(&self, record: &RawStateRecord) -> Result<VerifiedEntryBytes, StoreError> {
            let mut bytes = record.key.as_bytes().to_vec();
            bytes.extend_from_slice(record.value.as_bytes());
            Ok(VerifiedEntryBytes::from_independently_verified(bytes))
        }
    }

    #[test]
    fn practical_account_read_write_round_trip() {
        let address = AccountAddress::new([0x11; 20]);
        let account = AccountRecord {
            nonce: 5,
            ..AccountRecord::default()
        };
        let mut state = OfflineState::new(MemoryStore::default());
        state.write_account(address, &account).unwrap();
        assert_eq!(state.read_account(address).unwrap(), Some(account));
        assert_eq!(
            state
                .store()
                .get(OfflineState::<MemoryStore>::account_key(address).as_bytes())
                .unwrap(),
            Some(vec![0x81, 0xa1, b'n', 5])
        );
    }

    #[test]
    fn prepared_replacement_reads_old_and_does_not_commit() {
        let address = AccountAddress::new([0x22; 20]);
        let key = OfflineState::<MemoryStore>::account_key(address);
        let old = AccountRecord {
            nonce: 1,
            ..AccountRecord::default()
        };
        let new = AccountRecord {
            nonce: 2,
            ..AccountRecord::default()
        };
        let old_value = encode_account(&old).unwrap();
        let new_value = encode_account(&new).unwrap();
        let mut store = MemoryStore::default();
        store.put(key.as_bytes(), old_value.as_bytes()).unwrap();
        let mut initial = LatticeAccumulator::default();
        let old_record = RawStateRecord {
            key: key.clone(),
            value: old_value.clone(),
        };
        initial.add(&KeyValueMaterializer.materialize(&old_record).unwrap());

        let mut state = OfflineState::new(store);
        let prepared = state
            .prepare_replacement(
                &initial,
                RawStateRecord {
                    key: key.clone(),
                    value: new_value.clone(),
                },
                &KeyValueMaterializer,
            )
            .unwrap();
        assert_eq!(prepared.previous, Some(old_record));
        assert!(prepared.delta.removed.is_some());
        assert_eq!(prepared.accumulator_after.record_count(), 1);
        assert_eq!(
            state.store().get(key.as_bytes()).unwrap(),
            Some(old_value.into_bytes())
        );

        state.apply_database_update(&prepared.update).unwrap();
        assert_eq!(
            state.store().get(key.as_bytes()).unwrap(),
            Some(new_value.into_bytes())
        );
    }

    #[test]
    fn independent_entries_and_storage_length_are_checked() {
        let address = AccountAddress::new([3; 20]);
        let slot = StorageSlot::from_be_bytes([4; 32]);
        let key = OfflineState::<MemoryStore>::storage_key(address, slot);
        let value = encode_storage_value(StorageValue::from_be_bytes([5; 32]));
        let state = OfflineState::new(MemoryStore::default());
        let prepared = state
            .prepare_replacement(
                &LatticeAccumulator::default(),
                RawStateRecord { key, value },
                &KeyValueMaterializer,
            )
            .unwrap();
        assert_eq!(prepared.accumulator_after.record_count(), 1);
        assert_eq!(prepared.delta.before_record_count, 0);
    }
}
