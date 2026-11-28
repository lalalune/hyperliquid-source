use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_rlp::{Decodable, Encodable};
use rust_decimal::Decimal;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_alloy_evm_and_rpc(arg: &str) {
    let raw = arg.as_bytes();
    let factory = alloy_evm::EthEvmFactory::default();
    let db = alloy_evm::revm::database::EmptyDB::default();
    let env = EvmEnv::default();
    let mut evm = factory.create_evm(db, env);
    let tx = alloy_evm::revm::context::TxEnv::default();
    let _ = core::hint::black_box(evm.transact(tx));

    let mut s1 = raw;
    if let Ok(tx) = alloy_consensus::TxEnvelope::decode(&mut s1) {
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let _ = core::hint::black_box((tx.tx_hash(), buf));
    }
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionRequest>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Block>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionReceipt>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::FeeHistory>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Filter>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Log>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_engine::ExecutionPayloadV3>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_json_abi::JsonAbi>(arg));

    let mut hb = alloy_trie::HashBuilder::default();
    hb.add_leaf(alloy_trie::Nibbles::unpack(raw), raw);
    let _ = core::hint::black_box(hb.root());
    for hf in alloy_hardforks::EthereumHardfork::VARIANTS {
        let _ = core::hint::black_box((hf.name(), hf.mainnet_activation_block()));
    }
    let _ = core::hint::black_box(alloy_chains::Chain::from_id(raw.len() as u64 + 1));

    // jsonrpsee-types / jsonrpsee-core
    let _ = core::hint::black_box(serde_json::from_str::<jsonrpsee_types::Request<'_>>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<jsonrpsee_types::Response<'_, serde_json::Value>>(arg));
    let _ = core::hint::black_box(jsonrpsee_types::ErrorObject::owned(-32602, arg.to_string(), None::<()>));

    // rmp-serde + rust_decimal + ethers-core + curve25519 + k256
    let _ = core::hint::black_box(rmp_serde::from_slice::<serde_json::Value>(raw));
    let _ = core::hint::black_box(rmp_serde::to_vec_named(&arg));
    if let Ok(d) = arg.parse::<Decimal>() {
        let _ = core::hint::black_box((d.round_dp(4), d.checked_mul(d), d.checked_div(Decimal::TWO)));
    }
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Transaction>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Block<ethers_core::types::H256>>(arg));
    let mut sc_bytes = [0u8; 32];
    for (i, b) in raw.iter().take(32).enumerate() {
        sc_bytes[i] = *b;
    }
    let sc = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order(sc_bytes);
    let pt = &sc * &curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
    let _ = core::hint::black_box((pt.compress(), pt.to_montgomery()));
    let _ = core::hint::black_box(k256::ecdsa::SigningKey::from_slice(&sc_bytes));
    let _ = core::hint::black_box(k256::ecdsa::VerifyingKey::from_sec1_bytes(raw));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_alloy_evm_and_rpc(&arg);
    }
}
