//! Independently authored Rust reconstruction of node #115's signer admission
//! gate (`0x2bdb230` / `0x4d907c0`), action class getter (`0x36c2030`),
//! 92-entry class table (`0x79dd60`), and other-chain listed addresses
//! (`0x464946..0x464982`), from `staking-admission-gate-115`.

use std::collections::BTreeSet;

use crate::snapshot::SnapshotStore;

pub type Address = [u8; 20];

/// Exact status codes observed in `0x2bdb230` and `0x4d907c0`.
pub const STATUS_OK: u16 = 0x1a2;
pub const STATUS_UNAUTHORIZED_VALIDATOR: u16 = 0x7f;
pub const STATUS_UNKNOWN_USER: u16 = 0x5b;
pub const STATUS_REFUSED: u16 = 0x81;

/// Base raw action word subtracted by `0x36c2030` (`0x86`).
pub const ACTION_CLASS_TABLE_BASE: u16 = 0x86;

/// Exact 92-byte class table at `.rodata` `0x79dd60` (`0x86..=0xe1`).
/// Counts: class 0 = 1 (`0x9f`), class 1 = 1 (`0x9a`, plus all words `< 0x86`),
/// class 2 = 38, class 3 = 47, class 4 = 5 (`0xbe`, `0xbf`, `0xc1`, `0xcc`, `0xcd`).
pub const ACTION_CLASS_TABLE: [u8; 92] = [
    3, 2, 3, 3, 3, 3, 3, 3, 3, 2, 3, 2, 3, 3, 3, 3, // 0x86..=0x95
    2, 2, 3, 3, 1, 2, 3, 3, 3, 0, 3, 3, 3, 2, 2, 3, // 0x96..=0xa5
    3, 3, 2, 3, 3, 3, 3, 3, 2, 2, 3, 3, 3, 2, 2, 2, // 0xa6..=0xb5
    2, 2, 2, 2, 3, 2, 2, 3, 4, 4, 2, 4, 2, 2, 2, 2, // 0xb6..=0xc5
    3, 3, 2, 2, 3, 2, 4, 4, 3, 2, 3, 2, 2, 2, 3, 3, // 0xc6..=0xd5
    3, 3, 2, 3, 2, 2, 2, 2, 2, 3, 3, 3,             // 0xd6..=0xe1
];

/// Exact three 20-byte other-chain listed addresses at `.rodata` `0x464946`,
/// `0x46495a`, and `0x46496e` (`staking-admission-gate-115/listed.tsv`).
pub const OTHER_CHAIN_LISTED_ADDRESSES: [Address; 3] = [
    [
        0x34, 0x7e, 0x6c, 0x73, 0x76, 0xd3, 0x3a, 0x5c, 0x6c, 0x1d, 0x0d, 0xfe, 0x60, 0x6a, 0x49,
        0x02, 0xeb, 0x87, 0xcc, 0x86,
    ],
    [
        0xb9, 0x31, 0x0f, 0xf6, 0xca, 0xa9, 0x8c, 0xba, 0x94, 0x42, 0xb3, 0x66, 0x38, 0x76, 0xcb,
        0xab, 0xab, 0x0b, 0x5a, 0xc6,
    ],
    [
        0xbd, 0xca, 0xe9, 0x9d, 0xbc, 0x8f, 0xf0, 0x81, 0xdd, 0x36, 0xf3, 0x95, 0xb0, 0x56, 0x87,
        0xae, 0x71, 0x0b, 0xed, 0x49,
    ],
];

/// Five signer admission classes decoded from `0x79dd60`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SignerClass {
    /// Class 0: active validator signer only (`0x7f` on miss).
    ValidatorOnly = 0,
    /// Class 1: active validator or chain listed-signer set (`0x7f` on miss).
    ValidatorOrListed = 1,
    /// Class 2: any signer admitted unconditionally.
    AnySigner = 2,
    /// Class 3: known user resolved via user map / owner rows / second map (`0x5b` on miss).
    KnownUser = 3,
    /// Class 4: unconditionally refused (`0x81`).
    Refused = 4,
}

/// Reconstructs `0x36c2030`: words `< 0x86` map to index `0x14` (`0x9a`, class 1);
/// words `0x86..=0xe1` index `ACTION_CLASS_TABLE`; words `>= 0xe2` are out of table range.
pub fn action_class(raw_action: u16) -> Option<SignerClass> {
    let byte = if raw_action < ACTION_CLASS_TABLE_BASE {
        ACTION_CLASS_TABLE[0x14]
    } else {
        let idx = usize::from(raw_action - ACTION_CLASS_TABLE_BASE);
        *ACTION_CLASS_TABLE.get(idx)?
    };
    match byte {
        0 => Some(SignerClass::ValidatorOnly),
        1 => Some(SignerClass::ValidatorOrListed),
        2 => Some(SignerClass::AnySigner),
        3 => Some(SignerClass::KnownUser),
        4 => Some(SignerClass::Refused),
        _ => None,
    }
}

/// Boundary for the three-stage known-user lookup (`0x55fedb0` / inline `0x2bdb230`):
/// 1. User map (`exchange+0x3b80`) -> returns mapped 20-byte owner payload;
/// 2. Owner rows (`exchange+0x7c8`) -> returns `signer`;
/// 3. Second map (`exchange+0x3f8`) -> returns `signer`.
pub trait UserResolver {
    fn resolve_known_user(&self, signer: Address) -> Option<Address>;
}

/// Admitted signer payload (`status = 0x1a2` + 20-byte resolved address).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionOutcome {
    pub status: u16,
    pub resolved_address: Address,
}

/// Rejection reasons from `0x2bdb230` / `0x4d907c0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// Action word outside `0..=0xe1`.
    UnsupportedAction(u16),
    /// Status `0x7f`: signer is neither an active validator nor (for class 1) listed.
    UnauthorizedValidator,
    /// Status `0x5b`: signer not found in known-user stages (carries original signer).
    UnknownUser(Address),
    /// Status `0x81`: action class 4 is unconditionally refused.
    Refused,
}

impl AdmissionError {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            AdmissionError::UnsupportedAction(_) => None,
            AdmissionError::UnauthorizedValidator => Some(STATUS_UNAUTHORIZED_VALIDATOR),
            AdmissionError::UnknownUser(_) => Some(STATUS_UNKNOWN_USER),
            AdmissionError::Refused => Some(STATUS_REFUSED),
        }
    }
}

/// Reconstructs the signer admission gate (`0x2bdb230` / `0x4d907c0`).
///
/// `chain_byte == 3` selects `chain3_listed_set` (`0x64dfff8`); any other chain
/// byte selects `OTHER_CHAIN_LISTED_ADDRESSES` (`0x64e0000`).
pub fn admit_signer<U: UserResolver>(
    raw_action: u16,
    signer: Address,
    chain_byte: u8,
    snapshots: &SnapshotStore,
    chain3_listed_set: &BTreeSet<Address>,
    users: &U,
) -> Result<AdmissionOutcome, AdmissionError> {
    let class = action_class(raw_action).ok_or(AdmissionError::UnsupportedAction(raw_action))?;
    match class {
        SignerClass::ValidatorOnly => {
            if snapshots.is_active_validator(&signer).is_ok() {
                Ok(AdmissionOutcome {
                    status: STATUS_OK,
                    resolved_address: signer,
                })
            } else {
                Err(AdmissionError::UnauthorizedValidator)
            }
        }
        SignerClass::ValidatorOrListed => {
            if snapshots.is_active_validator(&signer).is_ok() {
                return Ok(AdmissionOutcome {
                    status: STATUS_OK,
                    resolved_address: signer,
                });
            }
            let is_listed = if chain_byte == 3 {
                chain3_listed_set.contains(&signer)
            } else {
                OTHER_CHAIN_LISTED_ADDRESSES.contains(&signer)
            };
            if is_listed {
                Ok(AdmissionOutcome {
                    status: STATUS_OK,
                    resolved_address: signer,
                })
            } else {
                Err(AdmissionError::UnauthorizedValidator)
            }
        }
        SignerClass::AnySigner => Ok(AdmissionOutcome {
            status: STATUS_OK,
            resolved_address: signer,
        }),
        SignerClass::KnownUser => match users.resolve_known_user(signer) {
            Some(resolved) => Ok(AdmissionOutcome {
                status: STATUS_OK,
                resolved_address: resolved,
            }),
            None => Err(AdmissionError::UnknownUser(signer)),
        },
        SignerClass::Refused => Err(AdmissionError::Refused),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{EpochSnapshot, ValidatorEntry};
    use std::collections::BTreeMap;

    struct MapUsers(BTreeMap<Address, Address>);
    impl UserResolver for MapUsers {
        fn resolve_known_user(&self, signer: Address) -> Option<Address> {
            self.0.get(&signer).copied()
        }
    }

    fn addr(b: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = b;
        a
    }

    #[test]
    fn class_table_counts_and_niche_match_node115_packet() {
        let mut counts = [0usize; 5];
        for w in 0x86u16..=0xe1u16 {
            let c = action_class(w).unwrap();
            counts[c as usize] += 1;
        }
        assert_eq!(counts, [1, 1, 38, 47, 5]);
        assert_eq!(action_class(0x9f), Some(SignerClass::ValidatorOnly));
        assert_eq!(action_class(0x9a), Some(SignerClass::ValidatorOrListed));
        assert_eq!(action_class(0x00), Some(SignerClass::ValidatorOrListed));
        assert_eq!(action_class(0x85), Some(SignerClass::ValidatorOrListed));
        assert_eq!(action_class(0xbe), Some(SignerClass::Refused));
        assert_eq!(action_class(0xe2), None);
    }

    #[test]
    fn admission_gate_enforces_all_five_classes_and_chain_selection() {
        let val = addr(1);
        let listed_c3 = addr(2);
        let agent = addr(3);
        let master = addr(4);
        let stranger = addr(9);

        let mut snaps = SnapshotStore::new(1);
        snaps.insert_snapshot(EpochSnapshot {
            epoch: 1,
            entries: vec![ValidatorEntry {
                key: [1u8; 32],
                signer: val,
                hot_address: val,
                stake: 100,
            }],
        });
        let c3 = BTreeSet::from([listed_c3]);
        let users = MapUsers(BTreeMap::from([(agent, master)]));

        // Class 0 (`0x9f`): validator only.
        assert_eq!(
            admit_signer(0x9f, val, 0, &snaps, &c3, &users),
            Ok(AdmissionOutcome {
                status: 0x1a2,
                resolved_address: val
            })
        );
        assert_eq!(
            admit_signer(0x9f, OTHER_CHAIN_LISTED_ADDRESSES[0], 0, &snaps, &c3, &users),
            Err(AdmissionError::UnauthorizedValidator)
        );

        // Class 1 (`0x9a` and `< 0x86`): validator or listed for chosen chain.
        assert_eq!(
            admit_signer(0x9a, OTHER_CHAIN_LISTED_ADDRESSES[1], 0, &snaps, &c3, &users),
            Ok(AdmissionOutcome {
                status: 0x1a2,
                resolved_address: OTHER_CHAIN_LISTED_ADDRESSES[1]
            })
        );
        assert_eq!(
            admit_signer(0x9a, OTHER_CHAIN_LISTED_ADDRESSES[1], 3, &snaps, &c3, &users),
            Err(AdmissionError::UnauthorizedValidator)
        );
        assert_eq!(
            admit_signer(0x10, listed_c3, 3, &snaps, &c3, &users),
            Ok(AdmissionOutcome {
                status: 0x1a2,
                resolved_address: listed_c3
            })
        );

        // Class 2 (`0x87`): any signer.
        assert_eq!(
            admit_signer(0x87, stranger, 0, &snaps, &c3, &users),
            Ok(AdmissionOutcome {
                status: 0x1a2,
                resolved_address: stranger
            })
        );

        // Class 3 (`0x86`): resolves known user or returns 0x5b with signer.
        assert_eq!(
            admit_signer(0x86, agent, 0, &snaps, &c3, &users),
            Ok(AdmissionOutcome {
                status: 0x1a2,
                resolved_address: master
            })
        );
        assert_eq!(
            admit_signer(0x86, stranger, 0, &snaps, &c3, &users),
            Err(AdmissionError::UnknownUser(stranger))
        );
        assert_eq!(AdmissionError::UnknownUser(stranger).status_code(), Some(0x5b));

        // Class 4 (`0xbe`): refused with 0x81.
        assert_eq!(
            admit_signer(0xbe, val, 0, &snaps, &c3, &users),
            Err(AdmissionError::Refused)
        );
        assert_eq!(AdmissionError::Refused.status_code(), Some(0x81));
    }
}
