use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_rlp::{Decodable, Encodable};
use rust_decimal::{Decimal, MathematicalOps as _, RoundingStrategy};
use std::collections::BTreeMap;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct WireMsg {
    tag: String,
    nums: Vec<u64>,
    map: BTreeMap<String, i64>,
    flag: bool,
    opt: Option<String>,
}

#[inline(never)]
fn touch_math_serde_rpc(arg: &str) {
    let raw = arg.as_bytes();

    // Deep ruint 1.18.0 Uint<256, 4> / Uint<128, 2> / Uint<512, 8>
    let a = ruint::aliases::U256::from(raw.len() as u64 + 17);
    let b = ruint::aliases::U256::from(raw.len() as u64 + 31);
    let _ = core::hint::black_box((
        a.checked_mul(b),
        a.checked_div(b),
        a.div_rem(b),
        a.widening_mul::<256, 4, 512, 8>(b),
        a.mul_mod(b, ruint::aliases::U256::from(997u64)),
        a.pow(ruint::aliases::U256::from(5u64)),
        ruint::aliases::U256::from_str_radix(arg, 16),
        ruint::aliases::U256::from_str_radix(arg, 10),
        format!("{a} {a:x} {a:X}"),
        serde_json::to_string(&a),
        serde_json::from_str::<ruint::aliases::U256>(arg),
    ));
    let mut rlp_out = Vec::new();
    alloy_rlp::Encodable::encode(&a, &mut rlp_out);
    let mut rlp_in = rlp_out.as_slice();
    let _ = core::hint::black_box(ruint::aliases::U256::decode(&mut rlp_in));

    // Deep rust_decimal 1.36.0
    if let Ok(d) = arg.parse::<Decimal>() {
        let _ = core::hint::black_box((
            d.checked_add(Decimal::ONE),
            d.checked_sub(Decimal::ONE),
            d.checked_mul(d),
            d.checked_div(Decimal::TWO),
            d.checked_rem(Decimal::TEN),
            d.round_dp_with_strategy(6, RoundingStrategy::MidpointAwayFromZero),
            d.round_dp_with_strategy(6, RoundingStrategy::ToZero),
            d.sqrt(),
            d.powi(3),
            d.exp(),
            d.ln(),
            d.normalize(),
            d.to_string(),
            Decimal::from_scientific(arg),
            serde_json::to_string(&d),
            serde_json::from_str::<Decimal>(arg),
        ));
    }

    // Deep rmp-serde 1.3.1 + serde_json 1.0.154 + jsonrpsee 0.26.0
    let msg = WireMsg {
        tag: arg.to_string(),
        nums: vec![1, 2, 3, raw.len() as u64],
        map: BTreeMap::from([(arg.to_string(), -42)]),
        flag: true,
        opt: Some(arg.to_string()),
    };
    let mp_named = rmp_serde::to_vec_named(&msg).unwrap_or_default();
    let mp_tuple = rmp_serde::to_vec(&msg).unwrap_or_default();
    let _ = core::hint::black_box(rmp_serde::from_slice::<WireMsg>(&mp_named));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WireMsg>(&mp_tuple));
    let _ = core::hint::black_box(rmp_serde::from_slice::<serde_json::Value>(raw));
    let js = serde_json::to_vec_pretty(&msg).unwrap_or_default();
    let _ = core::hint::black_box(serde_json::from_slice::<WireMsg>(&js));
    let _ = core::hint::black_box(serde_json::from_str::<Box<serde_json::value::RawValue>>(arg));

    let _ = core::hint::black_box(serde_json::from_str::<jsonrpsee_types::Request<'_>>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<jsonrpsee_types::Response<'_, serde_json::Value>>(arg));
    let _ = core::hint::black_box(jsonrpsee_types::ErrorObject::owned(-32602, arg.to_string(), None::<()>));

    // ethabi 18.0 + ethers-core 2.0.14
    if let Ok(contract) = serde_json::from_str::<ethabi::Contract>(arg) {
        for f in contract.functions() {
            let _ = core::hint::black_box((f.encode_input(&[]), f.decode_output(raw)));
        }
        for e in contract.events() {
            let _ = core::hint::black_box(e.signature());
        }
    }
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::transaction::eip712::TypedData>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::TransactionReceipt>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<ethers_core::types::Log>(arg));

    // alloy-evm 0.39.0 + revm 43.0.3 + alloy 2.5.0
    let factory = alloy_evm::EthEvmFactory::default();
    let db = alloy_evm::revm::database::EmptyDB::default();
    let mut evm = factory.create_evm(db, EvmEnv::default());
    let _ = core::hint::black_box(evm.transact(alloy_evm::revm::context::TxEnv::default()));
    let mut s1 = raw;
    if let Ok(tx) = alloy_consensus::TxEnvelope::decode(&mut s1) {
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let _ = core::hint::black_box((tx.tx_hash(), buf));
    }
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Block>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_engine::ExecutionPayloadV3>(arg));
    let mut hb = alloy_trie::HashBuilder::default();
    hb.add_leaf(alloy_trie::Nibbles::unpack(raw), raw);
    let _ = core::hint::black_box(hb.root());
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_math_serde_rpc(&arg);
    }
}
