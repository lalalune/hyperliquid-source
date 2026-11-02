//! Initial reply routing recovered from node94's greeting caller.
//!
//! This is the dispatch before state validation. A route is not permission to
//! trust a peer, and these Rust types do not reproduce the target's native ABI.

use core::fmt;

use super::reply::{HashReply, Reply};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Continue with the existing stream without a greeting state payload.
    ContinueStream,
    /// Further validation of the supplied state is required before proceeding.
    ValidateState,
}

/// The target caller's initial greeting rejection, independent of native tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRejection {
    Full,
    RateLimited,
    NoQuorumL1Hash,
    InconsistentGreeting,
}

impl fmt::Display for PeerRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Full => "Peer full",
            Self::RateLimited => "Rate limited by peer",
            Self::NoQuorumL1Hash => "Peer no quorum l1 hash",
            Self::InconsistentGreeting => "Peer inconsistent greeting",
        })
    }
}

impl std::error::Error for PeerRejection {}

pub(super) fn route(first: u8, reply: &Reply) -> Result<Route, PeerRejection> {
    match reply {
        Reply::Variant0 {
            hash: HashReply::Variant0 { .. } | HashReply::Variant1 { .. },
            ..
        } if first & 1 != 0 => Ok(Route::ValidateState),
        Reply::Variant0 { .. } | Reply::Variant1(_) => Err(PeerRejection::InconsistentGreeting),
        Reply::Variant2 => Err(PeerRejection::NoQuorumL1Hash),
        Reply::Variant3 if first == 0 => Ok(Route::ContinueStream),
        Reply::Variant3 => Err(PeerRejection::InconsistentGreeting),
        Reply::Variant4 => Err(PeerRejection::Full),
        Reply::Variant5 => Err(PeerRejection::RateLimited),
    }
}
