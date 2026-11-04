#![no_std]
#![forbid(unsafe_code)]
//! Safe logical projection of the selected node115 setDisplayName decisions.
//! This is not the complete action, storage mutation or wire implementation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    PriorKeyRejection,
    WrapperLimit,
    Empty,
    TooLong,
    TooShort,
    Duplicate,
    Unique,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    None,
    Erase,
    Upsert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub path: Path,
    pub outer_tag: u64,
    pub result_word: u64,
    pub mutation: Mutation,
}

const SUCCESS_TAG: u64 = 14;
const ERROR_TAG: u64 = 15;
const SUCCESS_WORD: u64 = 418;
const PRIOR_REJECTION_WORD: u64 = 288;
const WRAPPER_LIMIT_WORD: u64 = 344;
const LONG_ERROR_WORD: u64 = 226;
const SHORT_ERROR_WORD: u64 = 227;
const DUPLICATE_ERROR_WORD: u64 = 228;

/// Evaluate the selected normal-return branch order.
///
/// `duplicate` and `prior_key_rejection` are already-evaluated predicates from
/// the surrounding native path. This function does not inspect account keys or
/// execute an erase or upsert helper.
pub fn classify(length: u64, duplicate: bool, prior_key_rejection: bool) -> Decision {
    if prior_key_rejection {
        return Decision {
            path: Path::PriorKeyRejection,
            outer_tag: ERROR_TAG,
            result_word: PRIOR_REJECTION_WORD,
            mutation: Mutation::None,
        };
    }
    if length >= 101 {
        return Decision {
            path: Path::WrapperLimit,
            outer_tag: ERROR_TAG,
            result_word: WRAPPER_LIMIT_WORD,
            mutation: Mutation::None,
        };
    }
    if length == 0 {
        return Decision {
            path: Path::Empty,
            outer_tag: SUCCESS_TAG,
            result_word: SUCCESS_WORD,
            mutation: Mutation::Erase,
        };
    }
    if length > 20 {
        return Decision {
            path: Path::TooLong,
            outer_tag: ERROR_TAG,
            result_word: LONG_ERROR_WORD,
            mutation: Mutation::None,
        };
    }
    if length < 3 {
        return Decision {
            path: Path::TooShort,
            outer_tag: ERROR_TAG,
            result_word: SHORT_ERROR_WORD,
            mutation: Mutation::None,
        };
    }
    if duplicate {
        return Decision {
            path: Path::Duplicate,
            outer_tag: ERROR_TAG,
            result_word: DUPLICATE_ERROR_WORD,
            mutation: Mutation::None,
        };
    }
    Decision {
        path: Path::Unique,
        outer_tag: SUCCESS_TAG,
        result_word: SUCCESS_WORD,
        mutation: Mutation::Upsert,
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{Mutation, Path, classify};
    use std::string::String;
    use std::vec::Vec;

    fn path_name(path: Path) -> &'static str {
        match path {
            Path::PriorKeyRejection => "prior_rejection",
            Path::WrapperLimit => "wrapper_limit",
            Path::Empty => "empty",
            Path::TooLong => "too_long",
            Path::TooShort => "too_short",
            Path::Duplicate => "duplicate",
            Path::Unique => "unique",
        }
    }

    fn mutation_name(mutation: Mutation) -> &'static str {
        match mutation {
            Mutation::None => "none",
            Mutation::Erase => "erase",
            Mutation::Upsert => "upsert",
        }
    }

    #[test]
    fn frozen_native_branch_vectors() {
        let text = include_str!(
            "../../research/work-items/RE-010-display-name-path-115/branch-vectors.tsv"
        );
        let mut rows = 0;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 7, "malformed vector: {line}");
            let length: u64 = fields[0].parse().unwrap();
            let duplicate = fields[1] == "1";
            let prior = fields[2] == "1";
            let decision = classify(length, duplicate, prior);
            assert_eq!(path_name(decision.path), fields[3], "{line}");
            assert_eq!(
                decision.outer_tag,
                fields[4].parse::<u64>().unwrap(),
                "{line}"
            );
            assert_eq!(
                decision.result_word,
                fields[5].parse::<u64>().unwrap(),
                "{line}"
            );
            assert_eq!(mutation_name(decision.mutation), fields[6], "{line}");
            rows += 1;
        }
        assert_eq!(rows, 14);
    }

    #[test]
    fn boundary_order_and_u64_maximum() {
        assert_eq!(classify(0, true, false).mutation, Mutation::Erase);
        assert_eq!(classify(1, false, false).path, Path::TooShort);
        assert_eq!(classify(2, false, false).path, Path::TooShort);
        assert_eq!(classify(3, false, false).path, Path::Unique);
        assert_eq!(classify(20, true, false).path, Path::Duplicate);
        assert_eq!(classify(21, false, false).path, Path::TooLong);
        assert_eq!(classify(100, false, false).path, Path::TooLong);
        assert_eq!(classify(101, false, false).path, Path::WrapperLimit);
        assert_eq!(classify(u64::MAX, false, false).path, Path::WrapperLimit);
    }

    #[test]
    fn prior_rejection_dominates_every_later_branch() {
        for length in [0, 1, 3, 20, 21, 100, 101, u64::MAX] {
            let decision = classify(length, true, true);
            assert_eq!(decision.path, Path::PriorKeyRejection);
            assert_eq!(decision.result_word, 288);
            assert_eq!(decision.mutation, Mutation::None);
        }
    }

    #[test]
    fn duplicate_only_changes_the_admissible_length_range() {
        let mut output = String::new();
        for length in 0..=101 {
            let duplicate = classify(length, true, false);
            let unique = classify(length, false, false);
            if (3..=20).contains(&length) {
                assert_eq!(duplicate.path, Path::Duplicate);
                assert_ne!(duplicate, unique);
            } else {
                assert_eq!(duplicate, unique);
            }
            if length % 16 == 0 {
                output.push('.');
            }
        }
        assert_eq!(output.len(), 7);
    }
}
