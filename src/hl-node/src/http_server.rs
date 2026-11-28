//! Pure-std localhost HTTP/1.1 server for node #115 `/health`, `/info` (`info-api`),
//! and `/evm` EVM JSON-RPC (`evm-rpc`), with zero external dependencies.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use evm_rpc::{
    EVM_RPC_CORE_METHODS, EVM_RPC_EXTRA_METHODS, EVM_RPC_WRITE_FORWARD_METHOD,
    ExpensiveCallLimiter, FeeHistoryResult, JSONRPC_INVALID_PARAMS, JSONRPC_METHOD_NOT_FOUND, LimiterSelector,
    MethodRouter, PermitOutcome, compute_fee_history_range, decode_raw_tx_hex, parse_number_text,
    validate_log_filter_limits,
};
use global_constants::ChainName;
use info_api::node115_json_string_scanner::{Output as ScanOutput, scan as scan_json_string};
use info_api::request::{InfoRequestKind, parse_info_request_kind};
use info_api::router::{INFO_HTTP_PATH, RequestAccess, check_request_access};
use node115_abci::abci_hash::blake3_hash;

use crate::engine::{NodeEngine, format_hex_32};

const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct HttpServerConfig {
    pub bind_addr: SocketAddr,
    pub serve_info: bool,
    pub serve_evm_rpc: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub body: String,
}

struct ServerState {
    engine: Arc<RwLock<NodeEngine>>,
    serve_info: bool,
    serve_evm_rpc: bool,
    evm_router: MethodRouter<&'static str>,
    evm_limiter: Mutex<ExpensiveCallLimiter>,
}

/// Running pure-std localhost HTTP server with clean cooperative shutdown.
pub struct LocalHttpServer {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl LocalHttpServer {
    pub fn start(
        engine: Arc<RwLock<NodeEngine>>,
        cfg: HttpServerConfig,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(cfg.bind_addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;

        let mut evm_router = MethodRouter::new();
        for &m in &EVM_RPC_CORE_METHODS {
            let _ = evm_router.register(m, m);
        }
        for &m in &EVM_RPC_EXTRA_METHODS {
            let _ = evm_router.register(m, m);
        }
        let _ = evm_router.register(EVM_RPC_WRITE_FORWARD_METHOD, EVM_RPC_WRITE_FORWARD_METHOD);

        let state = Arc::new(ServerState {
            engine,
            serve_info: cfg.serve_info,
            serve_evm_rpc: cfg.serve_evm_rpc,
            evm_router,
            evm_limiter: Mutex::new(ExpensiveCallLimiter::new(16, 16, 5.0, 5.0)),
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, peer_addr)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        let _ = handle_connection(&mut stream, peer_addr.ip(), &state);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            local_addr,
            shutdown,
            handle: Some(handle),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    peer_ip: IpAddr,
    state: &ServerState,
) -> io::Result<()> {
    let Some((method, path, body)) = read_http_request(stream)? else {
        return Ok(());
    };

    let (status, reason, resp_body) = dispatch_request(&method, &path, &body, peer_ip, state);
    let reply = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
        resp_body.len()
    );
    stream.write_all(reply.as_bytes())?;
    stream.flush()
}

fn read_http_request(stream: &mut TcpStream) -> io::Result<Option<(String, String, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let header_end;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 32 * 1024 {
            return Ok(None);
        }
    }

    let head = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = head.lines();
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_len = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
            && let Ok(parsed) = v.trim().parse::<usize>()
        {
            content_len = parsed.min(MAX_HTTP_BODY_BYTES);
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);
    Ok(Some((method, path, body)))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn dispatch_request(
    method: &str,
    path: &str,
    body: &[u8],
    peer_ip: IpAddr,
    state: &ServerState,
) -> (u16, &'static str, String) {
    if method == "GET" && path == "/health" {
        let eng = state.engine.read().expect("engine read lock");
        let json = format!(
            "{{\"status\":\"ok\",\"chain\":\"{}\",\"height\":{},\"round\":{},\"committedRound\":{},\"abciStateRoot\":\"{}\",\"evmKvCount\":{},\"evmBlockGasLimit\":{},\"serveInfo\":{},\"serveEvmRpc\":{},\"subsystems\":26}}",
            eng.chain_display(),
            eng.latest_height(),
            eng.latest_round(),
            eng.committed_round(),
            eng.abci_state_root_hex(),
            eng.evm_kv_count(),
            eng.evm_block_gas_limit(),
            state.serve_info,
            state.serve_evm_rpc,
        );
        return (200, "OK", json);
    }

    if method == "POST" && path == INFO_HTTP_PATH {
        if !state.serve_info {
            return (
                404,
                "Not Found",
                "{\"error\":\"info server disabled\"}".to_string(),
            );
        }
        return handle_info_request(body, peer_ip, &state.engine);
    }

    if method == "POST" && (path == "/evm" || path == "/") {
        if !state.serve_evm_rpc {
            return (
                404,
                "Not Found",
                "{\"error\":\"evm rpc disabled\"}".to_string(),
            );
        }
        return handle_evm_rpc(body, state);
    }

    (404, "Not Found", "{\"error\":\"not found\"}".to_string())
}

fn handle_info_request(
    body: &[u8],
    peer_ip: IpAddr,
    engine: &Arc<RwLock<NodeEngine>>,
) -> (u16, &'static str, String) {
    let kind = match parse_info_request_kind(body) {
        Ok(k) => k,
        Err(err) => {
            return (
                400,
                "Bad Request",
                format!("{{\"error\":\"invalid info request\",\"detail\":\"{err:?}\"}}"),
            );
        }
    };

    if check_request_access(kind, peer_ip) == RequestAccess::RejectedNotLocalhost {
        return (
            403,
            "Forbidden",
            format!("{{\"error\":\"not from localhost: {peer_ip}\"}}"),
        );
    }

    let eng = engine.read().expect("engine read lock");
    let wire_name = kind.as_wire_name();
    let (acc_cs, ctr_cs, stg_cs) = eng.lt_hashes().checksums();
    let payload = match kind {
        InfoRequestKind::ExchangeStatus => format!(
            "{{\"type\":\"exchangeStatus\",\"chain\":\"{}\",\"height\":{},\"round\":{},\"committedRound\":{},\"abciStateRoot\":\"{}\",\"books\":{},\"activeTriggers\":{},\"activeTwaps\":{},\"beginBlockPhases\":{},\"ltHashes\":{{\"accounts\":\"{}\",\"contracts\":\"{}\",\"storage\":\"{}\"}}}}",
            eng.chain_display(),
            eng.latest_height(),
            eng.latest_round(),
            eng.committed_round(),
            eng.abci_state_root_hex(),
            eng.book_count(),
            eng.active_trigger_count(),
            eng.active_twap_count(),
            eng.last_begin_block_phases().len(),
            format_hex_32(&acc_cs),
            format_hex_32(&ctr_cs),
            format_hex_32(&stg_cs),
        ),
        InfoRequestKind::Meta | InfoRequestKind::AllPerpMetas | InfoRequestKind::PerpDexs => format!(
            "{{\"type\":\"{wire_name}\",\"chain\":\"{}\",\"height\":{},\"universe\":[],\"marginTables\":[]}}",
            eng.chain_display(),
            eng.latest_height(),
        ),
        InfoRequestKind::SpotMeta => format!(
            "{{\"type\":\"spotMeta\",\"chain\":\"{}\",\"height\":{},\"tokens\":[],\"universe\":[]}}",
            eng.chain_display(),
            eng.latest_height(),
        ),
        InfoRequestKind::ClearinghouseState | InfoRequestKind::SpotClearinghouseState => format!(
            "{{\"type\":\"{wire_name}\",\"chain\":\"{}\",\"height\":{},\"abciStateRoot\":\"{}\",\"marginSummary\":{{\"accountValue\":\"0.0\",\"totalMarginUsed\":\"0.0\"}},\"assetPositions\":[]}}",
            eng.chain_display(),
            eng.latest_height(),
            eng.abci_state_root_hex(),
        ),
        InfoRequestKind::OpenOrders | InfoRequestKind::FrontendOpenOrders => format!(
            "{{\"type\":\"{wire_name}\",\"height\":{},\"activeTriggers\":{},\"activeTwaps\":{},\"orders\":[]}}",
            eng.latest_height(),
            eng.active_trigger_count(),
            eng.active_twap_count(),
        ),
        InfoRequestKind::DelegatorSummary | InfoRequestKind::Delegations => format!(
            "{{\"type\":\"{wire_name}\",\"height\":{},\"pendingWithdrawalUsers\":{}}}",
            eng.latest_height(),
            eng.pending_staking_withdrawals_count(),
        ),
        InfoRequestKind::UserFees => format!(
            "{{\"type\":\"userFees\",\"height\":{},\"protocolFeeScalesCount\":{}}}",
            eng.latest_height(),
            node115_fees::solvency::PROTOCOL_FEE_SCALES.len(),
        ),
        InfoRequestKind::FileSnapshot => format!(
            "{{\"type\":\"fileSnapshot\",\"height\":{},\"abciStateRoot\":\"{}\",\"accountsHashChecksum\":\"{}\",\"storageHashChecksum\":\"{}\",\"restoredFrom\":{}}}",
            eng.latest_height(),
            eng.abci_state_root_hex(),
            format_hex_32(&acc_cs),
            format_hex_32(&stg_cs),
            eng.restored_from_checkpoint()
                .map_or_else(|| "null".to_string(), |h| h.to_string()),
        ),
        _ => format!(
            "{{\"type\":\"{wire_name}\",\"chain\":\"{}\",\"height\":{},\"abciStateRoot\":\"{}\",\"evmKvCount\":{}}}",
            eng.chain_display(),
            eng.latest_height(),
            eng.abci_state_root_hex(),
            eng.evm_kv_count(),
        ),
    };
    (200, "OK", payload)
}

fn handle_evm_rpc(body: &[u8], state: &ServerState) -> (u16, &'static str, String) {
    let Some(method_name) = extract_json_string_field(body, b"method") else {
        return (
            200,
            "OK",
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":{JSONRPC_INVALID_PARAMS},\"message\":\"Invalid params: missing method\"}}}}"
            ),
        );
    };
    let id_json = extract_json_id_token(body).unwrap_or_else(|| "1".to_string());

    let Ok(&canonical_method) = state.evm_router.get(&method_name) else {
        return (
            200,
            "OK",
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id_json},\"error\":{{\"code\":{JSONRPC_METHOD_NOT_FOUND},\"message\":\"Method not found\"}}}}"
            ),
        );
    };

    // Enforce `evm_rpc::ExpensiveCallLimiter` on call/estimateGas/getLogs paths.
    let maybe_selector = match canonical_method {
        "eth_call" | "eth_estimateGas" => Some(LimiterSelector::CallOrEstimateGas),
        "eth_getLogs" => Some(LimiterSelector::FilterLogs),
        _ => None,
    };
    if let Some(sel) = maybe_selector {
        let outcome = state
            .evm_limiter
            .lock()
            .expect("limiter lock")
            .try_acquire(sel);
        if outcome != PermitOutcome::Acquired {
            return (
                200,
                "OK",
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id_json},\"error\":{{\"code\":-32000,\"message\":\"rate limited\"}}}}"
                ),
            );
        }
    }

    let eng = state.engine.read().expect("engine read lock");
    let chain_id_num: u64 = match eng.chain() {
        ChainName::Mainnet => 999,
        ChainName::Testnet | ChainName::Sandbox | ChainName::Local => 998,
    };
    let result_json = match canonical_method {
        "eth_chainId" => format!("\"0x{chain_id_num:x}\""),
        "net_version" => format!("\"{chain_id_num}\""),
        "web3_clientVersion" => "\"hl-node/0.1.0-node115\"".to_string(),
        "eth_blockNumber" => format!("\"0x{:x}\"", eng.latest_height()),
        "eth_syncing" => "false".to_string(),
        "eth_gasPrice" | "eth_bigBlockGasPrice" => "\"0x3b9aca00\"".to_string(),
        "eth_usingBigBlocks" => {
            if eng.using_big_blocks() {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        "eth_maxPriorityFeePerGas" => "\"0x0\"".to_string(),
        "eth_getBlockByNumber" => format!(
            "{{\"number\":\"0x{:x}\",\"hash\":\"{}\",\"gasLimit\":\"0x{:x}\",\"transactions\":[]}}",
            eng.latest_height(),
            eng.abci_state_root_hex(),
            eng.evm_block_gas_limit(),
        ),
        "eth_feeHistory" => {
            let selector = parse_number_text("latest").expect("latest selector");
            let history = match compute_fee_history_range(5, selector, eng.latest_height()) {
                Ok(Some(range)) => FeeHistoryResult {
                    oldest_block: range.oldest_block,
                    base_fee_per_gas: vec![1_000_000_000],
                    gas_used_ratio: vec![0.0],
                    ..Default::default()
                },
                Ok(None) | Err(_) => FeeHistoryResult::default(),
            };
            history.to_string()
        }
        "eth_getLogs" => {
            if !validate_log_filter_limits(0, [0, 0, 0, 0]) {
                return (
                    200,
                    "OK",
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{id_json},\"error\":{{\"code\":{JSONRPC_INVALID_PARAMS},\"message\":\"filter limit exceeded\"}}}}"
                    ),
                );
            }
            "[]".to_string()
        }
        "eth_sendRawTransaction" => {
            let Some(raw_hex) = extract_first_param_string(body) else {
                if let Some(sel) = maybe_selector {
                    state.evm_limiter.lock().expect("limiter lock").release(sel);
                }
                return (
                    200,
                    "OK",
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{id_json},\"error\":{{\"code\":{JSONRPC_INVALID_PARAMS},\"message\":\"missing raw tx hex param\"}}}}"
                    ),
                );
            };
            match decode_raw_tx_hex(raw_hex.as_bytes()) {
                Ok(decoded) => {
                    let tx_hash = blake3_hash(&decoded);
                    format!("\"{}\"", format_hex_32(&tx_hash))
                }
                Err(_) => {
                    if let Some(sel) = maybe_selector {
                        state.evm_limiter.lock().expect("limiter lock").release(sel);
                    }
                    return (
                        200,
                        "OK",
                        format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{id_json},\"error\":{{\"code\":{JSONRPC_INVALID_PARAMS},\"message\":\"invalid raw tx hex\"}}}}"
                        ),
                    );
                }
            }
        }
        _ => format!(
            "{{\"method\":\"{canonical_method}\",\"blockNumber\":\"0x{:x}\",\"abciStateRoot\":\"{}\"}}",
            eng.latest_height(),
            eng.abci_state_root_hex(),
        ),
    };

    if let Some(sel) = maybe_selector {
        state.evm_limiter.lock().expect("limiter lock").release(sel);
    }

    (
        200,
        "OK",
        format!("{{\"jsonrpc\":\"2.0\",\"id\":{id_json},\"result\":{result_json}}}"),
    )
}

fn extract_json_string_field(body: &[u8], target_key: &[u8]) -> Option<String> {
    let mut cursor = 0usize;
    skip_ws(body, &mut cursor);
    if body.get(cursor) != Some(&b'{') {
        return None;
    }
    cursor += 1;
    let mut scratch = Vec::new();
    while cursor < body.len() {
        skip_ws(body, &mut cursor);
        if body.get(cursor) == Some(&b'}') {
            break;
        }
        if body.get(cursor) != Some(&b'"') {
            cursor += 1;
            continue;
        }
        cursor += 1;
        scratch.clear();
        let key = match scan_json_string(body, &mut cursor, &mut scratch).ok()? {
            ScanOutput::Borrowed(b) | ScanOutput::Scratch(b) => b.to_vec(),
        };
        skip_ws(body, &mut cursor);
        if body.get(cursor) != Some(&b':') {
            continue;
        }
        cursor += 1;
        skip_ws(body, &mut cursor);
        if key == target_key && body.get(cursor) == Some(&b'"') {
            cursor += 1;
            scratch.clear();
            let val = match scan_json_string(body, &mut cursor, &mut scratch).ok()? {
                ScanOutput::Borrowed(b) | ScanOutput::Scratch(b) => b.to_vec(),
            };
            return String::from_utf8(val).ok();
        }
    }
    None
}

fn extract_first_param_string(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let idx = text.find("\"params\"")?;
    let after = text[idx + 8..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('[')?.trim_start();
    let rest = after.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_json_id_token(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let idx = text.find("\"id\"")?;
    let after = text[idx + 4..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    if let Some(rest) = after.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(format!("\"{}\"", &rest[..end]));
    }
    let end = after
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after.len());
    if end == 0 {
        None
    } else {
        Some(after[..end].to_string())
    }
}

fn skip_ws(input: &[u8], cursor: &mut usize) {
    while let Some(&b) = input.get(*cursor) {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            *cursor += 1;
        } else {
            break;
        }
    }
}

/// Minimal pure-std HTTP/1.1 `GET` helper for loopback integration verification.
pub fn http_get(addr: SocketAddr, path: &str) -> io::Result<HttpResponse> {
    http_request(addr, "GET", path, "")
}

/// Minimal pure-std HTTP/1.1 `POST` helper for loopback integration verification.
pub fn http_post(addr: SocketAddr, path: &str, body: &str) -> io::Result<HttpResponse> {
    http_request(addr, "POST", path, body)
}

fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> io::Result<HttpResponse> {
    let mut stream = TcpStream::connect(addr)?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, resp_body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP response"))?;
    let status_code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status code"))?;
    Ok(HttpResponse {
        status_code,
        body: resp_body.to_string(),
    })
}
