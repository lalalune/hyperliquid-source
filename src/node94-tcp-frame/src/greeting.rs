//! The established request/reply-frame boundary of node #94's initial greeting.
//!
//! This is called after a connection exists. It preserves the reply payload for
//! the still-incomplete semantic decoder; receiving a frame is not accepting a
//! peer. No endpoint selection, retry, authentication or reconnect is supplied.

use core::fmt;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::deadlines::{self, DeadlineError};
use crate::{DecodedFrame, FrameLimits};

/// The two original greeting bytes and the separate reader timing flag.
///
/// Their protocol roles are not inferred from the reference source. The first
/// byte selects the observed response limit by zero versus nonzero; both bytes
/// are sent verbatim. The third transmitted byte is always zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub first: u8,
    pub second: u8,
    pub time_header: bool,
}

impl Request {
    #[must_use]
    pub const fn payload(self) -> [u8; 3] {
        [self.first, self.second, 0]
    }

    /// The exact caller-selected inclusive limit, also applied after LZ4.
    #[must_use]
    pub const fn reply_limits(self) -> FrameLimits {
        FrameLimits::new(if self.first == 0 {
            1_000
        } else {
            3_000_000_000
        })
    }
}

/// Which side of the request/reply-frame exchange failed.
#[derive(Debug)]
pub enum ExchangeError {
    Send(DeadlineError),
    Receive(DeadlineError),
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(error) => write!(f, "greeting send: {error}"),
            Self::Receive(error) => write!(f, "greeting receive: {error}"),
        }
    }
}

impl std::error::Error for ExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Send(error) | Self::Receive(error) => Some(error),
        }
    }
}

/// Sends the initial greeting and receives its complete reply frame.
///
/// Writes exactly `00 00 00 03 00 first second 00`, with the observed default
/// 20-second write deadline. The reply header is optionally timed at 40 seconds;
/// each payload chunk has a fresh 20 seconds. An active Tokio time driver is
/// required. No reply bytes are interpreted as a peer or protocol result here.
///
/// The caller must validate the returned payload before accepting the peer.
/// On error or cancellation, discard the stream unless its frame boundary can
/// independently be restored. This function does not flush or close the stream.
pub async fn exchange_frame<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
    request: Request,
) -> Result<DecodedFrame, ExchangeError> {
    // Every stream-field value takes the same raw branch for a 3-byte payload;
    // zero here assigns no port or peer role to that otherwise-unused argument.
    deadlines::write_frame(stream, &request.payload(), 0, None)
        .await
        .map_err(ExchangeError::Send)?;
    deadlines::read_frame(stream, request.reply_limits(), request.time_header)
        .await
        .map_err(ExchangeError::Receive)
}
