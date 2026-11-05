//! Node115 link-staking logical normal-state transition.
//! Independently authored types; native ABI, allocation and map layout are unclaimed.
use std::collections::{BTreeMap, BTreeSet};

pub type Key = [u8; 20];

/// The three row forms written by the observed request/finalize path.
/// These Rust variants do not claim the original enum representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationKind {
    Pending,
    TradingLinked,
    StakingLinked,
}

impl RelationKind {
    pub fn observed_tag(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::TradingLinked => 1,
            Self::StakingLinked => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relation {
    pub kind: RelationKind,
    pub peer: Key,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Request,
    Finalize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    MissingStakeKey,
    SameKeys,
    TradingAlreadyLinked,
    StakingAlreadyLinked,
    MissingPendingRequest,
}

impl LinkError {
    pub fn code(self) -> u8 {
        match self {
            Self::MissingStakeKey => 1,
            Self::SameKeys => 2,
            Self::TradingAlreadyLinked => 3,
            Self::StakingAlreadyLinked => 4,
            Self::MissingPendingRequest => 5,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::MissingStakeKey => "Staking user has no staked HYPE",
            Self::SameKeys => "Cannot link a staking user to itself",
            Self::TradingAlreadyLinked => "Trading user already has a link established",
            Self::StakingAlreadyLinked => "Staking user already has a link established",
            Self::MissingPendingRequest => "Trading user must request before staking user",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write {
    pub key: Key,
    pub relation: Relation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub result: Result<(), LinkError>,
    /// Actual logical upsert order, including two writes to an aliased key.
    pub writes: Vec<Write>,
}

impl Outcome {
    pub fn code(&self) -> u8 {
        self.result.err().map_or(0, LinkError::code)
    }

    /// Active native result discriminants only, not a native result struct.
    pub fn observed_tags(&self) -> (u8, u16) {
        if self.result.is_ok() {
            (0x0e, 0x1a2)
        } else {
            (0x0f, 0x16f)
        }
    }
}

fn linked(relation: Option<&Relation>) -> bool {
    relation.is_some_and(|row| row.kind != RelationKind::Pending)
}

/// Apply the complete logical normal path of wrapper 0x58c07d0.
/// The two forwarded keys swap roles between request and finalize.
/// Stake-key membership is inspected only for a request; no amount is read.
///
/// Maps contain stable rows with the three observed tags. Successful ordinary
/// allocation and valid map invariants are premises. This does not model the
/// captured container representation, allocation failure, panic/unwind, parent
/// admission gates, native memory ABI, wire decoding, signing or networking.
pub fn apply(
    mode: Mode,
    caller_key: Key,
    payload_key: Key,
    stake_keys: &BTreeSet<Key>,
    relations: &mut BTreeMap<Key, Relation>,
) -> Outcome {
    let (staking, trading) = match mode {
        Mode::Request => (payload_key, caller_key),
        Mode::Finalize => (caller_key, payload_key),
    };
    let error = match mode {
        Mode::Request => {
            if !stake_keys.contains(&staking) {
                Some(LinkError::MissingStakeKey)
            } else if staking == trading {
                Some(LinkError::SameKeys)
            } else if linked(relations.get(&trading)) {
                Some(LinkError::TradingAlreadyLinked)
            } else if linked(relations.get(&staking)) {
                Some(LinkError::StakingAlreadyLinked)
            } else {
                None
            }
        }
        Mode::Finalize => {
            let pending = relations
                .get(&trading)
                .is_some_and(|row| row.kind == RelationKind::Pending && row.peer == staking);
            if !pending {
                Some(LinkError::MissingPendingRequest)
            } else if linked(relations.get(&staking)) {
                Some(LinkError::StakingAlreadyLinked)
            } else {
                None
            }
        }
    };
    if let Some(error) = error {
        return Outcome {
            result: Err(error),
            writes: Vec::new(),
        };
    }
    let writes = match mode {
        Mode::Request => vec![Write {
            key: trading,
            relation: Relation {
                kind: RelationKind::Pending,
                peer: staking,
            },
        }],
        Mode::Finalize => vec![
            Write {
                key: trading,
                relation: Relation {
                    kind: RelationKind::TradingLinked,
                    peer: staking,
                },
            },
            Write {
                key: staking,
                relation: Relation {
                    kind: RelationKind::StakingLinked,
                    peer: trading,
                },
            },
        ],
    };
    for write in &writes {
        relations.insert(write.key, write.relation);
    }
    Outcome {
        result: Ok(()),
        writes,
    }
}
