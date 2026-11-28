use std::hint::black_box;
use alloy_rlp::{Decodable, Encodable};
use alloy_sol_types::{sol, SolCall, SolEvent, SolValue};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

sol! {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    event Transfer(address indexed from, address indexed to, uint256 value);
}

fn exercise_revm41() {
    let mut db = revm::database::InMemoryDB::default();
    let caller = alloy_primitives::Address::repeat_byte(0x11);
    let target = alloy_primitives::Address::repeat_byte(0x22);
    db.insert_account_info(
        caller,
        revm::state::AccountInfo {
            balance: alloy_primitives::U256::from(1_000_000_000_000u64),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
            account_id: None,
        },
    );
    // Simple PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    let code = revm::state::Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[
        0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ]));
    db.insert_account_info(
        target,
        revm::state::AccountInfo {
            balance: alloy_primitives::U256::ZERO,
            nonce: 1,
            code_hash: code.hash_slow(),
            code: Some(code),
            account_id: None,
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let tx = revm::context::TxEnv::builder()
        .caller(caller)
        .kind(revm::primitives::TxKind::Call(target))
        .gas_limit(100_000)
        .gas_price(1)
        .data(alloy_primitives::Bytes::from_static(b"\x01\x02\x03\x04"))
        .build()
        .unwrap();
    let _ = black_box(evm.transact(tx));
}

fn exercise_alloy_trie_consensus_sol() {
    // alloy-trie 0.9.5 HashBuilder + ProofRetainer + TrieMask
    let mut hb = alloy_trie::HashBuilder::default()
        .with_proof_retainer(alloy_trie::proof::ProofRetainer::from_iter([alloy_trie::Nibbles::from_nibbles([1, 2, 3])]));
    for i in 0u8..8 {
        let k = alloy_trie::Nibbles::unpack([i; 32]);
        hb.add_leaf(k, &[i; 16]);
    }
    let root = hb.root();
    let proofs = hb.take_proof_nodes();
    let _ = black_box((root, proofs, alloy_trie::TrieMask::new(0x0f0f)));

    // alloy-consensus 2.5.0 + eip2930 + eip7702 RLP + serde
    let al = alloy_eip2930::AccessList(vec![alloy_eip2930::AccessListItem {
        address: alloy_primitives::Address::repeat_byte(1),
        storage_keys: vec![alloy_primitives::B256::repeat_byte(2)],
    }]);
    let mut buf = Vec::new();
    al.encode(&mut buf);
    let _ = black_box(alloy_eip2930::AccessList::decode(&mut &buf[..]));
    let _ = black_box(serde_json::to_string(&al));

    let auth = alloy_eip7702::Authorization {
        chain_id: alloy_primitives::U256::from(999u64),
        address: alloy_primitives::Address::repeat_byte(3),
        nonce: 7,
    };
    buf.clear();
    auth.encode(&mut buf);
    let _ = black_box(alloy_eip7702::Authorization::decode(&mut &buf[..]));
    let _ = black_box(serde_json::to_string(&auth));

    let hdr = alloy_consensus::Header::default();
    buf.clear();
    hdr.encode(&mut buf);
    let _ = black_box(alloy_consensus::Header::decode(&mut &buf[..]));
    let _ = black_box(serde_json::to_string(&hdr));

    let tx_leg = alloy_consensus::TxLegacy::default();
    let tx_2930 = alloy_consensus::TxEip2930::default();
    let tx_1559 = alloy_consensus::TxEip1559::default();
    let tx_7702 = alloy_consensus::TxEip7702::default();
    for raw in [
        alloy_rlp::encode(&tx_leg),
        alloy_rlp::encode(&tx_2930),
        alloy_rlp::encode(&tx_1559),
        alloy_rlp::encode(&tx_7702),
    ] {
        let _ = black_box(raw);
    }
    let _ = black_box(alloy_consensus::TxLegacy::decode(&mut &alloy_rlp::encode(&tx_leg)[..]));
    let _ = black_box(alloy_consensus::TxEip2930::decode(&mut &alloy_rlp::encode(&tx_2930)[..]));
    let _ = black_box(alloy_consensus::TxEip1559::decode(&mut &alloy_rlp::encode(&tx_1559)[..]));
    let _ = black_box(alloy_consensus::TxEip7702::decode(&mut &alloy_rlp::encode(&tx_7702)[..]));

    // alloy-sol-types 1.7.3 ABI encode/decode
    let c1 = transferCall { to: alloy_primitives::Address::repeat_byte(5), amount: alloy_primitives::U256::from(12345u64) };
    let enc1 = c1.abi_encode();
    let _ = black_box(transferCall::abi_decode(&enc1));
    let c2 = swapCall {
        amount0Out: alloy_primitives::U256::from(100u64),
        amount1Out: alloy_primitives::U256::from(200u64),
        to: alloy_primitives::Address::repeat_byte(6),
        data: alloy_primitives::Bytes::from_static(b"swap"),
    };
    let enc2 = c2.abi_encode();
    let _ = black_box(swapCall::abi_decode(&enc2));
    let _ = black_box((alloy_primitives::Address::repeat_byte(1), alloy_primitives::U256::from(9u64), String::from("hl")).abi_encode());
    let _ = black_box(Transfer::SIGNATURE_HASH);

    // ruint 1.21.1 arithmetic + radix + div_rem + mul_mod + serde + RLP
    let a = ruint::Uint::<256, 4>::from_str_radix(black_box("1234567890123456789012345678901234567890"), 10).unwrap();
    let b = ruint::Uint::<256, 4>::from_str_radix(black_box("deadbeefcafe0123456789abcdef"), 16).unwrap();
    let m = ruint::Uint::<256, 4>::from(1_000_000_007u64);
    let _ = black_box((a.div_rem(b), a.mul_mod(b, m), a.pow_mod(b, m), a.inv_mod(m), a.to_string(), format!("{a:#x}")));
    let a512 = ruint::Uint::<512, 8>::from(a) * ruint::Uint::<512, 8>::from(b);
    let _ = black_box(a512.div_rem(ruint::Uint::<512, 8>::from(m)));

    // keccak-asm 0.1.9
    use keccak_asm::Digest;
    let mut k = keccak_asm::Keccak256::new();
    k.update(black_box(b"hyperliquid evm state root"));
    let _ = black_box(k.finalize());
}

fn main() {
    exercise_revm41();
    exercise_alloy_trie_consensus_sol();
}
