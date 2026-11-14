//! The two gates around the id at the end of `0x3c48b40` (`0x3c48f23..0x3c49000`).
//!
//! * index above `0x1869e` (99,998): the caller returns the 15-byte diagnostic `too many tokens`
//!   (string at `0x7bc148`) before any id is derived.
//! * membership of the id in a container keyed by 16 bytes: `0x3cd39b0` compares keys as two
//!   byte-swapped qwords at `0x3cd3cc2..0x3cd3ce8`, i.e. byte-lexicographic order, which is
//!   `[u8; 16]` order. An occupied entry (result tag 1 at `0x3c48fc4`) returns
//!   `token_id already exists` (`0x7bc131`, 23 bytes); a vacant entry continues into
//!   `0x3f19f10` / `0x3f1a750` with the index in `rdx` (from `[rsp+8]`, set at `0x3c48f7a`).
//!
//! The native container has two storage forms (converted inside `0x3cd39b0`); the flat branch of
//! `0x3f19f10` stores `rdx` beside the key, the tree branch was not traced for a value. Only key
//! membership is therefore modelled, with a `BTreeSet`.

use std::collections::BTreeSet;

use crate::{token_id, Error, TokenSpec, ID_LEN};

/// `cmp rdx,0x1869e; jbe` at `0x3c48f23`.
pub const MAX_INDEX: u64 = 0x1869e;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    TooManyTokens,
    TokenIdAlreadyExists,
    Encode(Error),
}

impl RegisterError {
    /// The diagnostic the caller returns for the two native errors.
    pub fn message(&self) -> &'static str {
        match self {
            RegisterError::TooManyTokens => "too many tokens",
            RegisterError::TokenIdAlreadyExists => "token_id already exists",
            RegisterError::Encode(_) => "name of 2^32 bytes or more is not modelled",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TokenIds {
    ids: BTreeSet<[u8; ID_LEN]>,
}

impl TokenIds {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn contains(&self, id: &[u8; ID_LEN]) -> bool {
        self.ids.contains(id)
    }

    /// Derive the id for `(spec, index)` and record it. On any error the set is unchanged.
    pub fn register(&mut self, spec: &TokenSpec<'_>, index: u64) -> Result<[u8; ID_LEN], RegisterError> {
        if index > MAX_INDEX {
            return Err(RegisterError::TooManyTokens);
        }
        let id = token_id(spec, index).map_err(RegisterError::Encode)?;
        if !self.ids.insert(id) {
            return Err(RegisterError::TokenIdAlreadyExists);
        }
        Ok(id)
    }
}
