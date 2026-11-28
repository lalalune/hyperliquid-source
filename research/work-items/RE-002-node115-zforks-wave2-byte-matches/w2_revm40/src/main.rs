use alloy_consensus::Transaction as _;
use alloy_rlp::{Decodable, Encodable};
use ark_ec::{pairing::Pairing, AffineRepr, VariableBaseMSM};
use ark_ff::Field;
use revm::{ExecuteCommitEvm, InspectEvm, MainBuilder, MainContext};
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_revm40_full(arg: &str) {
    let raw = arg.as_bytes();
    let mut db = revm::database::CacheDB::new(revm::database::EmptyDB::default());
    let target = revm::primitives::Address::from([0x22u8; 20]);
    let code = revm::state::Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(raw));
    db.insert_account_info(
        target,
        revm::state::AccountInfo {
            balance: revm::primitives::U256::from(10_000_000u64),
            nonce: 2,
            code_hash: code.hash_slow(),
            code: Some(code),
            account_id: None,
        },
    );
    let mut state = revm::database::StateBuilder::new()
        .with_database(db)
        .with_bundle_update()
        .build();
    for spec in [
        revm::primitives::hardfork::SpecId::HOMESTEAD,
        revm::primitives::hardfork::SpecId::ISTANBUL,
        revm::primitives::hardfork::SpecId::LONDON,
        revm::primitives::hardfork::SpecId::CANCUN,
        revm::primitives::hardfork::SpecId::PRAGUE,
        revm::primitives::hardfork::SpecId::OSAKA,
    ] {
        let mut ctx = revm::Context::mainnet().with_db(&mut state);
        ctx.cfg.spec = spec;
        let mut evm = ctx.build_mainnet_with_inspector(revm::inspector::NoOpInspector {});
        let tx = revm::context::TxEnv::builder()
            .caller(revm::primitives::Address::ZERO)
            .kind(revm::primitives::TxKind::Call(target))
            .gas_limit(1_000_000)
            .gas_price(10)
            .data(revm::primitives::Bytes::copy_from_slice(raw))
            .build_fill();
        let _ = core::hint::black_box(evm.inspect_tx(tx.clone()));
        let _ = core::hint::black_box(evm.transact_commit(tx));
    }
    state.merge_transitions(revm::database::states::bundle_state::BundleRetention::Reverts);
    let _ = core::hint::black_box(state.take_bundle());

    for spec in [
        revm::precompile::PrecompileSpecId::HOMESTEAD,
        revm::precompile::PrecompileSpecId::BYZANTIUM,
        revm::precompile::PrecompileSpecId::ISTANBUL,
        revm::precompile::PrecompileSpecId::BERLIN,
        revm::precompile::PrecompileSpecId::CANCUN,
        revm::precompile::PrecompileSpecId::PRAGUE,
        revm::precompile::PrecompileSpecId::OSAKA,
    ] {
        let pre = revm::precompile::Precompiles::new(spec);
        for addr in pre.addresses() {
            if let Some(p) = pre.get(addr) {
                let _ = core::hint::black_box(p.execute(raw, 10_000_000, 0));
            }
        }
    }
}

#[inline(never)]
fn touch_alloy_and_ark(arg: &str) {
    let raw = arg.as_bytes();
    // alloy-consensus RLP + JSON + signature recovery
    let mut s1 = raw;
    if let Ok(tx) = alloy_consensus::TxEnvelope::decode(&mut s1) {
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let _ = core::hint::black_box((tx.tx_hash(), tx.gas_limit(), tx.nonce(), buf));
    }
    let mut s2 = raw;
    if let Ok(rcpt) = alloy_consensus::ReceiptEnvelope::decode(&mut s2) {
        let mut buf = Vec::new();
        rcpt.encode(&mut buf);
        let _ = core::hint::black_box(buf);
    }
    let mut s3 = raw;
    if let Ok(hdr) = alloy_consensus::Header::decode(&mut s3) {
        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        let _ = core::hint::black_box((hdr.hash_slow(), buf));
    }
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionRequest>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Block>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::TransactionReceipt>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::FeeHistory>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Filter>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::Log>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_rpc_types_eth::EIP1186AccountProofResponse>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_json_abi::JsonAbi>(arg));
    let _ = core::hint::black_box(serde_json::from_str::<alloy_consensus::Header>(arg));

    // alloy-trie deep proof + nibbles + branch
    let mut hb = alloy_trie::HashBuilder::default().with_proof_retainer(
        alloy_trie::proof::ProofRetainer::from_iter([alloy_trie::Nibbles::unpack(raw)]),
    );
    hb.add_leaf(alloy_trie::Nibbles::unpack(b"01"), raw);
    hb.add_leaf(alloy_trie::Nibbles::unpack(b"02"), b"val");
    hb.add_branch(alloy_trie::Nibbles::unpack(b"03"), alloy_primitives::B256::ZERO, true);
    let root = hb.root();
    let _ = core::hint::black_box((root, hb.take_proof_nodes()));

    // ark-bls12-381 & ark-bn254
    let g1 = ark_bls12_381::G1Affine::generator();
    let g2 = ark_bls12_381::G2Affine::generator();
    let fr = ark_bls12_381::Fr::from(raw.len() as u64 + 5);
    let _ = core::hint::black_box((
        ark_bls12_381::G1Projective::msm(&[g1, g1], &[fr, fr]),
        ark_bls12_381::G2Projective::msm(&[g2, g2], &[fr, fr]),
        ark_bls12_381::Bls12_381::multi_pairing([g1], [g2]),
        fr.inverse(),
    ));
    let bg1 = ark_bn254::G1Affine::generator();
    let bg2 = ark_bn254::G2Affine::generator();
    let bfr = ark_bn254::Fr::from(raw.len() as u64 + 7);
    let _ = core::hint::black_box((
        ark_bn254::G1Projective::msm(&[bg1, bg1], &[bfr, bfr]),
        ark_bn254::G2Projective::msm(&[bg2, bg2], &[bfr, bfr]),
        ark_bn254::Bn254::multi_pairing([bg1], [bg2]),
        bfr.inverse(),
    ));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_revm40_full(&arg);
        touch_alloy_and_ark(&arg);
    }
}
