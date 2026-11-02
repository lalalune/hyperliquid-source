#![no_std]
#![forbid(unsafe_code)]

pub const BODY_STATE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Route {
    PreBodyStateFailure = 0,
    PostBodyContextMissing = 1,
    PostBodyStateFailure = 2,
    RestorePriorState = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bracket {
    pub route: Route,
    pub body_state: Option<u8>,
    pub restored: Option<u8>,
}

/// Pure projection conditional on reaching the bracket and normal body return.
/// This does not access TLS or invoke a runtime body or panic handler.
pub fn bracket(prior: u8, after: u8, context_present: bool) -> Bracket {
    let (route, restored) = if prior == 2 {
        return Bracket {
            route: Route::PreBodyStateFailure,
            body_state: None,
            restored: None,
        };
    } else if !context_present {
        (Route::PostBodyContextMissing, None)
    } else if after != 2 {
        (Route::PostBodyStateFailure, None)
    } else {
        (Route::RestorePriorState, Some(prior))
    };
    Bracket {
        route,
        body_state: Some(BODY_STATE),
        restored,
    }
}

/// Observed save of +0x44/+0x45 and clear of low byte +0x44, not full restore.
pub fn saved_flags(word: u16) -> (u16, u16) {
    (word, word & 0xff00)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_entry_never_enters_and_missing_context_never_restores() {
        assert_eq!(bracket(2, 2, false).body_state, None);
        assert_eq!(bracket(9, 2, false).restored, None);
        assert_eq!(bracket(9, 2, true).restored, Some(9));
        assert_eq!(saved_flags(0xabcd), (0xabcd, 0xab00));
    }
}
