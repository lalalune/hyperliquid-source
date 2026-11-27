//! Independently authored Rust reconstruction of Hyperliquid node #115 `net_utils`
//! (target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//!
//! Covers all 12 observed `net_utils` source files (`async_sleep_retry`, `channel`,
//! `ip_semaphore`, `rate_limiter`, `rw_lock`, `tcp/{lz4_stats,read,tcp_client,
//! tcp_listener,tcp_stream,traffic_recorder,write}`) and integrates the verified
//! node #115 LZ4, TCP framing, greeting, gossip, and HTTP/2 transport micro-crates.

pub mod gossip;
pub mod ip_semaphore;
pub mod lz4;
pub mod primitives;
pub mod rate_limiter;
pub mod tcp;

/// Re-exports of verified node #115 low-level transport & HTTP/2 framing micro-crates.
pub mod framing {
    pub use node115_frame_stream as frame_stream;
    pub use node115_h2_framing as h2_framing;
    pub use node115_host_ip_gates as host_ip_gates;
    pub use node115_http_header_writer as http_header_writer;
    pub use node115_listener_prefix as listener_prefix;
    pub use node115_newline_requests as newline_requests;
    pub use node115_owned_frame_send as owned_frame_send;
    pub use node115_owned_tcp_receive as owned_tcp_receive;
    pub use node115_tcp_compression_plan as tcp_compression_plan;
    pub use node115_tcp_frame_plan as tcp_frame_plan;
    pub use node115_tcp_stream_frame_lz4 as tcp_stream_frame_lz4;
    pub use node115_write_progress as write_progress;
}

pub use bincode_fork;
pub use gossip::{GossipRpcRequest, GossipRpcResponse, PeerEntry};
pub use ip_semaphore::{IpSemaphore, IpSemaphorePermit, SemaphoreError};
pub use lz4::{Lz4Error, compress_prepend_size, decompress_size_prepended, should_compress_for_port};
pub use primitives::{
    BoundedChannel, ChannelError, ProfiledRwLock, RetryExhausted, RetryPolicy, sleep_retry,
};
pub use rate_limiter::{AlertConfig, RateLimitDecision, RateLimiter};
pub use tcp::{
    DEFAULT_MAX_FRAME_BYTES, DEFAULT_WRITE_TIMEOUT_SECS, Direction, FramedTcpStream,
    LZ4_STATS_WINDOW_SECS, Lz4Stats, TRAFFIC_RECORDER_WINDOW_SECS, TcpClient, TcpError,
    TcpListener, TrafficRecorder, encode_frame, read_bincode_frame, read_frame,
    write_bincode_frame, write_frame,
};
