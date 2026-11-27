//! TCP 5-byte framed transport, LZ4 stats, traffic recorder, `TcpClient`, and
//! `TcpListener` matching node #115 `net_utils/src/tcp/*`.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::time::{Duration, Instant};

use bincode_fork::{Decode, DecodeError, Encode, EncodeError, decode_from_slice, encode_to_vec, standard};
use node115_tcp_frame_plan::{CHUNK_BYTES, Header, OverLimit, admit, decode_header, next_chunk};

use crate::lz4::{Lz4Error, compress_prepend_size, decompress_size_prepended, should_compress_for_port};

/// Observed write timeout constant in node #115 `net_utils/src/tcp/write.rs`
/// (`0x2b7a193: movabsq $0x404e000000000000` => `60.0` seconds).
pub const DEFAULT_WRITE_TIMEOUT_SECS: f64 = 60.0;

/// Observed LZ4 stats reporting window in `net_utils/src/tcp/lz4_stats.rs`
/// (`0x478540b -> .rodata 0x458f40` => `300.0` seconds).
pub const LZ4_STATS_WINDOW_SECS: f64 = 300.0;

/// Observed LZ4 ratio warning threshold in `net_utils/src/tcp/lz4_stats.rs`
/// (`0x47857c0: movabs $0x3fe0000000000000` => `0.5`).
pub const LZ4_STATS_RATIO_WARN_THRESHOLD: f64 = 0.5;

/// Observed traffic recorder reporting window in `net_utils/src/tcp/traffic_recorder.rs`
/// (`0x4781d3a -> .rodata 0x458cd8` => `30.0` seconds).
pub const TRAFFIC_RECORDER_WINDOW_SECS: f64 = 30.0;

/// Observed `TcpListener` accept error retry sleep in `net_utils/src/tcp/tcp_listener.rs`
/// (`0x2afb0d4: movabs $0x3ff0000000000000` => `1.0` second).
pub const ACCEPT_RETRY_SLEEP_SECS: f64 = 1.0;

/// Default listener maximum frame payload limit (`node115-listener-prefix`).
pub const DEFAULT_MAX_FRAME_BYTES: u64 = node115_listener_prefix::LISTENER_LIMIT;

/// Frame direction matching `.rodata` `0x7e1c9c` (`"in"`, `"out"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
}

/// Compression statistics matching `net_utils/src/tcp/lz4_stats.rs` (`"tcp_lz4/"`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lz4DirectionCounters {
    pub frames: u64,
    pub compressed_frames: u64,
    pub raw_bytes: u64,
    pub wire_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct Lz4Stats {
    pub window: Duration,
    pub window_start: Instant,
    pub inbound: Lz4DirectionCounters,
    pub outbound: Lz4DirectionCounters,
}

impl Default for Lz4Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Lz4Stats {
    pub fn new() -> Self {
        Self {
            window: Duration::from_secs_f64(LZ4_STATS_WINDOW_SECS),
            window_start: Instant::now(),
            inbound: Lz4DirectionCounters::default(),
            outbound: Lz4DirectionCounters::default(),
        }
    }

    pub fn record(&mut self, dir: Direction, raw_bytes: usize, wire_bytes: usize, compressed: bool) {
        let c = match dir {
            Direction::In => &mut self.inbound,
            Direction::Out => &mut self.outbound,
        };
        c.frames += 1;
        if compressed {
            c.compressed_frames += 1;
        }
        c.raw_bytes += raw_bytes as u64;
        c.wire_bytes += wire_bytes as u64;
    }

    pub fn metric_prefix(dir: Direction, label: &str) -> String {
        format!("tcp_lz4/{}_{}", dir.as_str(), label)
    }

    pub fn compression_ratio(&self, dir: Direction) -> f64 {
        let c = match dir {
            Direction::In => &self.inbound,
            Direction::Out => &self.outbound,
        };
        if c.raw_bytes == 0 {
            1.0
        } else {
            c.wire_bytes as f64 / c.raw_bytes as f64
        }
    }
}

/// Per-peer and aggregate TCP traffic recorder matching
/// `net_utils/src/tcp/traffic_recorder.rs` (`30.0`s window, `"tcp_bytes"`).
#[derive(Clone, Debug)]
pub struct TrafficRecorder {
    pub window: Duration,
    pub window_start: Instant,
    pub in_bytes_by_ip: HashMap<IpAddr, u64>,
    pub out_bytes_by_ip: HashMap<IpAddr, u64>,
    pub total_in_bytes: u64,
    pub total_out_bytes: u64,
}

impl Default for TrafficRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficRecorder {
    pub fn new() -> Self {
        Self {
            window: Duration::from_secs_f64(TRAFFIC_RECORDER_WINDOW_SECS),
            window_start: Instant::now(),
            in_bytes_by_ip: HashMap::new(),
            out_bytes_by_ip: HashMap::new(),
            total_in_bytes: 0,
            total_out_bytes: 0,
        }
    }

    pub fn record(&mut self, dir: Direction, peer: IpAddr, bytes: usize) {
        let n = bytes as u64;
        match dir {
            Direction::In => {
                *self.in_bytes_by_ip.entry(peer).or_insert(0) += n;
                self.total_in_bytes += n;
            }
            Direction::Out => {
                *self.out_bytes_by_ip.entry(peer).or_insert(0) += n;
                self.total_out_bytes += n;
            }
        }
    }

    pub fn reset(&mut self, now: Instant) {
        self.in_bytes_by_ip.clear();
        self.out_bytes_by_ip.clear();
        self.total_in_bytes = 0;
        self.total_out_bytes = 0;
        self.window_start = now;
    }
}

/// Errors produced by framed TCP read/write/client operations, preserving exact
/// node #115 diagnostic prefixes.
#[derive(Debug)]
pub enum TcpError {
    Io(io::Error),
    OverLimit { payload_len: u32, maximum: u64 },
    FrameTooLarge(usize),
    Lz4(Lz4Error),
    BincodeDecode(DecodeError),
    BincodeEncode(EncodeError),
    NotConnected,
    IpNotV4(IpAddr),
    Connect(io::Error),
    Write(io::Error),
    Read(io::Error),
}

impl core::fmt::Display for TcpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "tcp io err: {e}"),
            Self::OverLimit {
                payload_len,
                maximum,
            } => write!(f, "tcp frame length {payload_len} exceeds limit {maximum}"),
            Self::FrameTooLarge(n) => write!(f, "tcp outgoing frame length {n} exceeds u32::MAX"),
            Self::Lz4(e) => write!(f, "{e}"),
            Self::BincodeDecode(e) => write!(f, "TcpRead::bincode err: {e:?}"),
            Self::BincodeEncode(e) => write!(f, "TcpWrite::bincode err: {e:?}"),
            Self::NotConnected => write!(f, "TcpClient not connected"),
            Self::IpNotV4(ip) => write!(f, "ip not v4: {ip}"),
            Self::Connect(e) => write!(f, "TcpClient connect {e}"),
            Self::Write(e) => write!(f, "TcpClient write {e}"),
            Self::Read(e) => write!(f, "TcpClient read {e}"),
        }
    }
}

impl std::error::Error for TcpError {}

/// Encode a payload into node #115's 5-byte framed wire representation
/// (`[u32 BE wire_len, u8 compressed_flag] || body`), honoring the exact
/// compression policy (`< 1025` bytes or port `3998`/`3999` => raw flag `0`;
/// otherwise LZ4 size-prepended flag `1`).
pub fn encode_frame(payload: &[u8], port: u16) -> Result<(Vec<u8>, bool), TcpError> {
    let (body, compressed) = if should_compress_for_port(payload.len(), port).is_some() {
        (compress_prepend_size(payload).map_err(TcpError::Lz4)?, true)
    } else {
        (payload.to_vec(), false)
    };
    let wire_len = u32::try_from(body.len()).map_err(|_| TcpError::FrameTooLarge(body.len()))?;
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(&wire_len.to_be_bytes());
    out.push(u8::from(compressed));
    out.extend_from_slice(&body);
    Ok((out, compressed))
}

/// Write a single 5-byte framed message to `writer`, returning `(wire_bytes, compressed)`.
pub fn write_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    port: u16,
) -> Result<(usize, bool), TcpError> {
    let (frame, compressed) = encode_frame(payload, port)?;
    writer.write_all(&frame).map_err(TcpError::Write)?;
    writer.flush().map_err(TcpError::Write)?;
    Ok((frame.len(), compressed))
}

/// Read a single 5-byte framed message from `reader`, using node #115's
/// `node115-tcp-frame-plan` admission and `CHUNK_BYTES = 4_000_000` chunked reads,
/// followed by size-checked LZ4 decompression when `header.flag == 1`.
pub fn read_frame<R: Read>(
    reader: &mut R,
    max_wire_bytes: u64,
    max_decoded_bytes: u64,
) -> Result<(Vec<u8>, Header), TcpError> {
    let mut hdr_bytes = [0u8; 5];
    reader.read_exact(&mut hdr_bytes).map_err(TcpError::Read)?;
    let header = decode_header(&hdr_bytes);
    let plan = admit(header, max_wire_bytes).map_err(|OverLimit| TcpError::OverLimit {
        payload_len: header.payload_len,
        maximum: max_wire_bytes,
    })?;

    let mut raw = vec![0u8; plan.payload_len as usize];
    let mut completed = 0u64;
    while let Some((start, end)) = next_chunk(plan.payload_len, completed) {
        debug_assert!(end - start <= CHUNK_BYTES);
        reader
            .read_exact(&mut raw[start as usize..end as usize])
            .map_err(TcpError::Read)?;
        completed = end;
    }

    if plan.decompress_after_read {
        let decoded = decompress_size_prepended(&raw, max_decoded_bytes).map_err(TcpError::Lz4)?;
        Ok((decoded, header))
    } else {
        Ok((raw, header))
    }
}

/// Encode `val` with `bincode-fork` standard config and transmit as a framed TCP message.
pub fn write_bincode_frame<W: Write, E: Encode>(
    writer: &mut W,
    val: E,
    port: u16,
) -> Result<(usize, bool), TcpError> {
    let bytes = encode_to_vec(val, standard()).map_err(TcpError::BincodeEncode)?;
    write_frame(writer, &bytes, port)
}

/// Receive a framed TCP message and decode `D` using `bincode-fork` with `bincode_limit`.
pub fn read_bincode_frame<R: Read, D: Decode>(
    reader: &mut R,
    max_wire_bytes: u64,
    max_decoded_bytes: u64,
    bincode_limit: Option<u64>,
) -> Result<D, TcpError> {
    let (payload, _hdr) = read_frame(reader, max_wire_bytes, max_decoded_bytes)?;
    let cfg = match bincode_limit {
        None => standard(),
        Some(n) => standard().with_limit_bytes(n),
    };
    let (val, _consumed) =
        decode_from_slice::<D>(&payload, cfg).map_err(TcpError::BincodeDecode)?;
    Ok(val)
}

/// Synchronous TCP stream wrapper integrating framing, LZ4 stats, and traffic recording.
#[derive(Debug)]
pub struct FramedTcpStream {
    stream: StdTcpStream,
    peer_addr: SocketAddr,
    max_wire_bytes: u64,
    max_decoded_bytes: u64,
}

impl FramedTcpStream {
    pub fn new(stream: StdTcpStream, max_wire_bytes: u64, max_decoded_bytes: u64) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let _ = stream.set_nodelay(true);
        let _ = stream.set_write_timeout(Some(Duration::from_secs_f64(DEFAULT_WRITE_TIMEOUT_SECS)));
        Ok(Self {
            stream,
            peer_addr,
            max_wire_bytes,
            max_decoded_bytes,
        })
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn send_bytes(
        &mut self,
        payload: &[u8],
        lz4_stats: Option<&mut Lz4Stats>,
        traffic: Option<&mut TrafficRecorder>,
    ) -> Result<(), TcpError> {
        let (wire_len, compressed) = write_frame(&mut self.stream, payload, self.peer_addr.port())?;
        if let Some(stats) = lz4_stats {
            stats.record(Direction::Out, payload.len(), wire_len, compressed);
        }
        if let Some(rec) = traffic {
            rec.record(Direction::Out, self.peer_addr.ip(), wire_len);
        }
        Ok(())
    }

    pub fn recv_bytes(
        &mut self,
        lz4_stats: Option<&mut Lz4Stats>,
        traffic: Option<&mut TrafficRecorder>,
    ) -> Result<Vec<u8>, TcpError> {
        let (payload, hdr) = read_frame(&mut self.stream, self.max_wire_bytes, self.max_decoded_bytes)?;
        let wire_len = 5 + hdr.payload_len as usize;
        if let Some(stats) = lz4_stats {
            stats.record(Direction::In, payload.len(), wire_len, hdr.flag == 1);
        }
        if let Some(rec) = traffic {
            rec.record(Direction::In, self.peer_addr.ip(), wire_len);
        }
        Ok(payload)
    }

    pub fn send_bincode<E: Encode>(&mut self, val: E) -> Result<(), TcpError> {
        let bytes = encode_to_vec(val, standard()).map_err(TcpError::BincodeEncode)?;
        self.send_bytes(&bytes, None, None)
    }

    pub fn recv_bincode<D: Decode>(&mut self, limit: Option<u64>) -> Result<D, TcpError> {
        let bytes = self.recv_bytes(None, None)?;
        let cfg = match limit {
            None => standard(),
            Some(n) => standard().with_limit_bytes(n),
        };
        let (val, _) = decode_from_slice::<D>(&bytes, cfg).map_err(TcpError::BincodeDecode)?;
        Ok(val)
    }
}

/// Framed TCP client matching `net_utils/src/tcp/tcp_client.rs`.
#[derive(Debug)]
pub struct TcpClient {
    addr: SocketAddr,
    desc: String,
    connect_timeout: Duration,
    max_wire_bytes: u64,
    max_decoded_bytes: u64,
    stream: Option<FramedTcpStream>,
}

impl TcpClient {
    pub fn new(addr: SocketAddr, desc: impl Into<String>) -> Result<Self, TcpError> {
        if !addr.ip().is_ipv4() {
            return Err(TcpError::IpNotV4(addr.ip()));
        }
        Ok(Self {
            addr,
            desc: desc.into(),
            connect_timeout: Duration::from_secs(5),
            max_wire_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_decoded_bytes: DEFAULT_MAX_FRAME_BYTES,
            stream: None,
        })
    }

    pub fn desc(&self) -> &str {
        &self.desc
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn connect(&mut self) -> Result<(), TcpError> {
        let raw = StdTcpStream::connect_timeout(&self.addr, self.connect_timeout)
            .map_err(TcpError::Connect)?;
        let framed = FramedTcpStream::new(raw, self.max_wire_bytes, self.max_decoded_bytes)
            .map_err(TcpError::Connect)?;
        self.stream = Some(framed);
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.stream = None;
    }

    pub fn send_bincode_and_read_response<Req: Encode, Resp: Decode>(
        &mut self,
        req: Req,
        bincode_limit: Option<u64>,
    ) -> Result<Resp, TcpError> {
        let stream = self.stream.as_mut().ok_or(TcpError::NotConnected)?;
        if let Err(e) = stream.send_bincode(req) {
            self.stream = None;
            return Err(e);
        }
        match stream.recv_bincode(bincode_limit) {
            Ok(resp) => Ok(resp),
            Err(e) => {
                self.stream = None;
                Err(e)
            }
        }
    }
}

/// Framed TCP listener matching `net_utils/src/tcp/tcp_listener.rs`.
#[derive(Debug)]
pub struct TcpListener {
    inner: StdTcpListener,
    max_wire_bytes: u64,
    max_decoded_bytes: u64,
}

impl TcpListener {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = StdTcpListener::bind(addr)?;
        Ok(Self {
            inner,
            max_wire_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_decoded_bytes: DEFAULT_MAX_FRAME_BYTES,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn accept(&self) -> io::Result<(FramedTcpStream, SocketAddr)> {
        let (raw, addr) = self.inner.accept()?;
        let framed = FramedTcpStream::new(raw, self.max_wire_bytes, self.max_decoded_bytes)?;
        Ok((framed, addr))
    }
}
