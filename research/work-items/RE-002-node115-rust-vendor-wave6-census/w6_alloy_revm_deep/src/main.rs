use std::hint::black_box;
use alloy_rlp::{Decodable, Encodable};
use alloy_sol_types::{sol, SolCall, SolEvent, SolValue};
use revm::{Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

sol! {
    struct Order {
        address maker;
        uint256 price;
        uint256 size;
        bytes extra;
    }
    function batchFill(Order[] calldata orders, address[] calldata users, uint256[] calldata amounts) external returns (bytes32);
    function multicall(bytes[] calldata data) external returns (bytes[] memory results);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Swap(address indexed sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out, address indexed to);
}

fn exercise_revm41_deep() {
    let mem_db = revm::database::InMemoryDB::default();
    let mut state = revm::database::State::builder()
        .with_database(mem_db)
        .with_bundle_update()
        .build();
    let caller = alloy_primitives::Address::repeat_byte(0x11);
    let target = alloy_primitives::Address::repeat_byte(0x22);

    // Build evm with State<InMemoryDB> & test Call + Create + EIP1559 + EIP2930 + EIP7702 + precompiles!
    let mut evm = Context::mainnet().with_db(&mut state).build_mainnet();
    let tx_call = revm::context::TxEnv::builder()
        .caller(caller)
        .kind(revm::primitives::TxKind::Call(target))
        .gas_limit(200_000)
        .gas_price(2)
        .gas_priority_fee(Some(1))
        .value(alloy_primitives::U256::from(100u64))
        .data(alloy_primitives::Bytes::from_static(b"\x01\x02\x03\x04"))
        .build()
        .unwrap();
    let _ = black_box(evm.transact_commit(tx_call));

    let tx_create = revm::context::TxEnv::builder()
        .caller(caller)
        .kind(revm::primitives::TxKind::Create)
        .gas_limit(500_000)
        .gas_price(2)
        .data(alloy_primitives::Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xf3]))
        .build()
        .unwrap();
    let _ = black_box(evm.transact(tx_create));

    // Also exercise revm precompiles directly (Prague/Cancun: bls12_381, kzg, bn128, modexp, blake2f, ecrecover)
    let pre = revm::precompile::Precompiles::prague();
    for addr in pre.addresses() {
        if let Some(p) = pre.get(addr) {
            let _ = black_box(p.execute(black_box(&[0u8; 192]), 1_000_000, 0));
        }
    }
    let _ = black_box(state.take_bundle());
}

fn exercise_alloy_trie_sol_consensus() {
    // alloy-trie 0.9.5 ordered_trie_root_with_encoder + trie_root_unhashed + TrieAccount + BranchNodeCompact
    let items: Vec<Vec<u8>> = (0u8..8).map(|i| vec![i; 16]).collect();
    let r1 = alloy_trie::root::ordered_trie_root_with_encoder(&items, |item, buf| item.encode(buf));
    let _ = black_box(r1);
    let pairs: Vec<(alloy_primitives::Address, alloy_trie::TrieAccount)> = (0u8..8)
        .map(|i| (alloy_primitives::Address::repeat_byte(i), alloy_trie::TrieAccount::default()))
        .collect();
    let r2 = alloy_trie::root::state_root_unhashed(pairs);
    let _ = black_box(r2);
    let acc = alloy_trie::TrieAccount::default();
    let mut enc = Vec::new();
    acc.encode(&mut enc);
    let _ = black_box(alloy_trie::TrieAccount::decode(&mut &enc[..]));
    let mut hb = alloy_trie::HashBuilder::default()
        .with_proof_retainer(alloy_trie::proof::ProofRetainer::from_iter([
            alloy_trie::Nibbles::from_nibbles([0, 1]),
            alloy_trie::Nibbles::from_nibbles([2, 3]),
        ]))
        .with_updates(true);
    for i in 0u8..16 {
        hb.add_leaf(alloy_trie::Nibbles::unpack([i; 32]), &[i; 20]);
    }
    let root = hb.root();
    let proofs = hb.take_proof_nodes();
    let (_, updates) = hb.split();
    let _ = black_box((root, proofs, updates));

    // alloy-sol-types 1.7.3 complex ABI encoding/decoding + SolEvent::decode_log
    let bf = batchFillCall {
        orders: vec![Order {
            maker: alloy_primitives::Address::repeat_byte(1),
            price: alloy_primitives::U256::from(1000u64),
            size: alloy_primitives::U256::from(500u64),
            extra: alloy_primitives::Bytes::from_static(b"hl"),
        }],
        users: vec![alloy_primitives::Address::repeat_byte(2)],
        amounts: vec![alloy_primitives::U256::from(99u64)],
    };
    let bfe = bf.abi_encode();
    let _ = black_box(batchFillCall::abi_decode(&bfe));
    let mc = multicallCall { data: vec![alloy_primitives::Bytes::from(bfe)] };
    let mce = mc.abi_encode();
    let _ = black_box(multicallCall::abi_decode(&mce));
    let packed = (alloy_primitives::Address::repeat_byte(1), alloy_primitives::U256::from(42u64), vec![1u8, 2, 3]).abi_encode_packed();
    let _ = black_box(packed);
    let log = alloy_primitives::Log::new_unchecked(
        alloy_primitives::Address::repeat_byte(1),
        vec![Approval::SIGNATURE_HASH, alloy_primitives::B256::repeat_byte(2), alloy_primitives::B256::repeat_byte(3)],
        alloy_primitives::Bytes::from(vec![0u8; 32]),
    );
    let _ = black_box(Approval::decode_log(&log));
    let _ = black_box(Swap::decode_log(&log));

    // alloy-consensus 2.1.1 TxEnvelope / ReceiptEnvelope / Signed RLP + serde
    let rec_env = alloy_consensus::ReceiptEnvelope::Eip1559(alloy_consensus::ReceiptWithBloom::new(
        alloy_consensus::Receipt {
            status: alloy_consensus::Eip658Value::Eip658(true),
            cumulative_gas_used: 21000,
            logs: vec![log],
        },
        alloy_primitives::Bloom::default(),
    ));
    let mut rbuf = Vec::new();
    rec_env.encode(&mut rbuf);
    let _ = black_box(alloy_consensus::ReceiptEnvelope::<alloy_primitives::Log>::decode(&mut &rbuf[..]));
    let _ = black_box(serde_json::to_string(&rec_env));

    // ruint 1.18.0 div_rem / knuth / radix / serde
    let a = ruint::Uint::<256, 4>::from_str_radix(black_box("1234567890123456789012345678901234567890"), 10).unwrap();
    let b = ruint::Uint::<256, 4>::from_str_radix(black_box("deadbeefcafe0123456789abcdef"), 16).unwrap();
    let m = ruint::Uint::<256, 4>::from(1_000_000_007u64);
    let _ = black_box((a.div_rem(b), a.mul_mod(b, m), a.pow_mod(b, m), a.inv_mod(m), a.to_string(), format!("{a:#x}")));
    let a512 = ruint::Uint::<512, 8>::from(a) * ruint::Uint::<512, 8>::from(b);
    let _ = black_box(a512.div_rem(ruint::Uint::<512, 8>::from(m)));
}

fn main() {
    exercise_revm41_deep();
    exercise_alloy_trie_sol_consensus();
}
