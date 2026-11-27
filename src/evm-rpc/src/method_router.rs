//! Node #115 `evm_rpc/src/method_router.rs` reconstruction.
//!
//! Grounded directly in `0x2a05f60` (26 methods), `0x2e375a0` (`net_version`,
//! `web3_clientVersion`), `0x17512f3` (`eth_sendRawTransaction`), and
//! `RE-011-evm-permit-routing-115` (duplicate-rejecting merge at `0x2e37920`,
//! `"Method not found"` at `0x453cf0`).

use std::collections::BTreeMap;

pub const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
pub const JSONRPC_INVALID_PARAMS: i32 = -32602;
pub const JSONRPC_INTERNAL_ERROR: i32 = -32603;
pub const JSONRPC_SERVER_ERROR: i32 = -32000;

/// Exact 26 JSON-RPC methods registered in order by `0x2a05f60` (`evm_rpc/src/method_router.rs`).
pub const EVM_RPC_CORE_METHODS: [&str; 26] = [
    "eth_blockNumber",
    "eth_call",
    "eth_chainId",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_gasPrice",
    "eth_getBalance",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getBlockReceipts",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getCode",
    "eth_getLogs",
    "eth_getStorageAt",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionByHash",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_maxPriorityFeePerGas",
    "eth_syncing",
    "eth_bigBlockGasPrice",
    "eth_getSystemTxsByBlockHash",
    "eth_getSystemTxsByBlockNumber",
    "eth_usingBigBlocks",
];

/// Additional 2 RPC methods registered in `0x2e375a0`.
pub const EVM_RPC_EXTRA_METHODS: [&str; 2] = ["net_version", "web3_clientVersion"];

/// Write-forwarder RPC method registered in `0x17512f3` (`evm_rpc/src/evm_write_forwarder.rs`).
pub const EVM_RPC_WRITE_FORWARD_METHOD: &str = "eth_sendRawTransaction";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouterError {
    DuplicateMethod(String),
    MethodNotFound(String),
}

impl RouterError {
    pub const fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::DuplicateMethod(_) => JSONRPC_INTERNAL_ERROR,
            Self::MethodNotFound(_) => JSONRPC_METHOD_NOT_FOUND,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::DuplicateMethod(_) => "Duplicate method registration",
            Self::MethodNotFound(_) => "Method not found",
        }
    }
}

/// Exact duplicate-rejecting method table matching `0x2e37920` / `0x2e38640`.
#[derive(Clone, Debug, Default)]
pub struct MethodRouter<H> {
    methods: BTreeMap<String, H>,
}

impl<H> MethodRouter<H> {
    pub fn new() -> Self {
        Self {
            methods: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, name: impl Into<String>, handler: H) -> Result<(), RouterError> {
        let name = name.into();
        if self.methods.contains_key(&name) {
            return Err(RouterError::DuplicateMethod(name));
        }
        self.methods.insert(name, handler);
        Ok(())
    }

    /// Merge `other` into `self`, rejecting any duplicate method name BEFORE
    /// mutating `self` (matching the preflight check at `0x2e37920`).
    pub fn merge(&mut self, other: Self) -> Result<(), RouterError> {
        for key in other.methods.keys() {
            if self.methods.contains_key(key) {
                return Err(RouterError::DuplicateMethod(key.clone()));
            }
        }
        self.methods.extend(other.methods);
        Ok(())
    }

    pub fn get(&self, method: &str) -> Result<&H, RouterError> {
        self.methods
            .get(method)
            .ok_or_else(|| RouterError::MethodNotFound(method.to_string()))
    }

    pub fn len(&self) -> usize {
        self.methods.len()
    }

    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}
