#![no_std]
#![forbid(unsafe_code)]

/// Selected branch outcome; diagnostic/trap labels describe the target only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Route {
    DigestMismatch = 0,
    PreHelperAssertion = 1,
    PostHelperUnwrap = 2,
    ReturnFetchedPrefix = 3,
}

/// Conditional normal-call protocol at node94 0x23ecd70.
/// This neither hashes, clones, fetches nor returns a native state object.
pub fn route(
    incoming: &[u8; 32],
    local: &[u8; 32],
    optional_word: u64,
    input_word: u64,
    helper_result: u64,
) -> Route {
    let same = incoming == local;
    if !same {
        Route::DigestMismatch
    } else if optional_word != 0 && input_word == 0 {
        Route::PreHelperAssertion
    } else if helper_result == 0x8000_0000_0000_0040 {
        Route::ReturnFetchedPrefix
    } else {
        Route::PostHelperUnwrap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_rejection_dominates_other_failure_and_success() {
        let a = [0; 32];
        let mut b = a;
        b[31] = 1;
        assert_eq!(
            route(&a, &b, 1, 0, 0x8000_0000_0000_0040),
            Route::DigestMismatch
        );
        assert_eq!(
            route(&a, &a, 1, 0, 0x8000_0000_0000_0040),
            Route::PreHelperAssertion
        );
        assert_eq!(
            route(&a, &a, 0, 0, 0x8000_0000_0000_0040),
            Route::ReturnFetchedPrefix
        );
    }
}
