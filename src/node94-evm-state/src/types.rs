use crate::error::DecodeError;

pub const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

macro_rules! fixed_bytes {
    ($name:ident, $length:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const LENGTH: usize = $length;

            #[must_use]
            pub const fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }

            #[must_use]
            pub const fn into_bytes(self) -> [u8; $length] {
                self.0
            }
        }

        impl From<[u8; $length]> for $name {
            fn from(value: [u8; $length]) -> Self {
                Self::new(value)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = DecodeError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let actual = value.len();
                let bytes = value.try_into().map_err(|_| DecodeError::WrongLength {
                    context: stringify!($name),
                    expected: $length,
                    actual,
                })?;
                Ok(Self(bytes))
            }
        }
    };
}

fixed_bytes!(AccountAddress, 20);
fixed_bytes!(CodeHash, 32);

/// A storage slot in canonical EVM big-endian byte order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageSlot([u8; 32]);

impl StorageSlot {
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn from_native_le_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self(bytes)
    }

    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn to_native_le_bytes(self) -> [u8; 32] {
        let mut bytes = self.0;
        bytes.reverse();
        bytes
    }
}

/// A stored U256 value in canonical EVM big-endian byte order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageValue([u8; 32]);

impl StorageValue {
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn from_native_le_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self(bytes)
    }

    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn to_native_le_bytes(self) -> [u8; 32] {
        let mut bytes = self.0;
        bytes.reverse();
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRecord {
    /// Canonical big-endian U256 bytes.
    pub balance: [u8; 32],
    pub nonce: u64,
    pub code_hash: CodeHash,
}

impl Default for AccountRecord {
    fn default() -> Self {
        Self {
            balance: [0; 32],
            nonce: 0,
            code_hash: CodeHash::new(EMPTY_CODE_HASH),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JumpTable {
    pub head: u8,
    pub bits: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip7702Code {
    pub delegated_address: AccountAddress,
    pub version: u64,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredCode {
    LegacyRaw(Vec<u8>),
    LegacyAnalyzed {
        bytecode: Vec<u8>,
        original_len: u64,
        jump_table: JumpTable,
    },
    /// The outer fields are known, but nested list element encodings are unresolved.
    Eof,
    Eip7702(Eip7702Code),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateKey {
    Account(AccountAddress),
    ContractCode(CodeHash),
    Storage {
        address: AccountAddress,
        slot: StorageSlot,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StateTable {
    Account,
    ContractCode,
    Storage,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SerializedDatabaseKey(Vec<u8>);

impl SerializedDatabaseKey {
    pub(crate) fn new_validated(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SerializedValue {
    Account(Vec<u8>),
    ContractCode(Vec<u8>),
    Storage([u8; 32]),
}

impl SerializedValue {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Account(bytes) | Self::ContractCode(bytes) => bytes,
            Self::Storage(bytes) => bytes,
        }
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Account(bytes) | Self::ContractCode(bytes) => bytes,
            Self::Storage(bytes) => bytes.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawStateRecord {
    pub key: SerializedDatabaseKey,
    pub value: SerializedValue,
}
