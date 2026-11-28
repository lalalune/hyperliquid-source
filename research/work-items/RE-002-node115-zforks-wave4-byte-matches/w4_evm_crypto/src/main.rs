use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_sol_types::SolValue;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hmac::Mac as _;
use k256::ecdsa::signature::{Signer as _, Verifier as _};
use sha2_10::Digest as _;
use tikv_jemallocator::Jemalloc;
use tiny_keccak::Hasher as _;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn touch_alloy_trie_and_sol(arg: &str) {
    let raw = arg.as_bytes();

    // Deep alloy-trie: HashBuilder, BranchNode, BranchNodeCompact, TrieNode, ProofRetainer, proof verify
    let mut hb = alloy_trie::HashBuilder::default().with_proof_retainer(
        alloy_trie::proof::ProofRetainer::from_iter([
            alloy_trie::Nibbles::unpack(raw),
            alloy_trie::Nibbles::unpack(b"aa"),
            alloy_trie::Nibbles::unpack(b"ab"),
        ]),
    );
    let pairs = [
        (b"0001".as_slice(), b"v1".as_slice()),
        (b"0002", b"v2"),
        (b"0010", b"v3"),
        (b"0100", b"v4"),
        (b"1000", raw),
    ];
    for (k, v) in pairs {
        hb.add_leaf(alloy_trie::Nibbles::unpack(k), v);
    }
    hb.add_branch(alloy_trie::Nibbles::unpack(b"2000"), B256::ZERO, false);
    let root = hb.root();
    let proofs = hb.take_proof_nodes();
    let proof_vecs: Vec<Bytes> = proofs.into_nodes_sorted().into_iter().map(|(_, b)| b).collect();
    let _ = core::hint::black_box(alloy_trie::proof::verify_proof(
        root,
        alloy_trie::Nibbles::unpack(b"0001"),
        Some(b"v1".to_vec()),
        proof_vecs.iter(),
    ));
    let mut rlp_slice = raw;
    if let Ok(node) = alloy_trie::nodes::TrieNode::decode(&mut rlp_slice) {
        let mut out = Vec::new();
        node.encode(&mut out);
        let _ = core::hint::black_box(out);
    }
    let _ = core::hint::black_box(alloy_trie::root::storage_root_unhashed(
        [(B256::ZERO, U256::from(raw.len() as u64 + 1))],
    ));

    // Deep alloy-sol-types ABI encode/decode/params/packed
    let tup = (
        Address::ZERO,
        Address::from([0x11; 20]),
        U256::from(raw.len() as u64 + 100),
        7u64,
        Bytes::copy_from_slice(raw),
    );
    let enc = tup.abi_encode();
    let _ = core::hint::black_box(<(Address, Address, U256, u64, Bytes)>::abi_decode(&enc));
    let enc_p = tup.abi_encode_params();
    let _ = core::hint::black_box(<(Address, Address, U256, u64, Bytes)>::abi_decode_params(&enc_p));
    let _ = core::hint::black_box(tup.abi_encode_packed());
    let _ = core::hint::black_box((U256::from(42u64), Address::ZERO, arg.to_string()).abi_encode());
    let _ = core::hint::black_box(<(U256, Address, String)>::abi_decode(raw));
}

#[inline(never)]
fn touch_crypto_deep(arg: &str) {
    let raw = arg.as_bytes();
    let mut key32 = [1u8; 32];
    for (i, b) in raw.iter().take(32).enumerate() {
        key32[i] ^= *b;
    }

    // k256 ECDSA sign + verify + recover + schnorr
    if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&key32) {
        let sig: k256::ecdsa::Signature = sk.sign(raw);
        let vk = sk.verifying_key();
        let _ = core::hint::black_box(vk.verify(raw, &sig));
        if let Ok((rsig, recid)) = sk.sign_prehash_recoverable(&key32) {
            let _ = core::hint::black_box(k256::ecdsa::VerifyingKey::recover_from_prehash(
                &key32, &rsig, recid,
            ));
        }
    }
    if let Ok(ssk) = k256::schnorr::SigningKey::from_bytes(&key32) {
        let ssig = ssk.sign(raw);
        let _ = core::hint::black_box(ssk.verifying_key().verify(raw, &ssig));
    }

    // p256 ECDSA sign + verify
    if let Ok(psk) = p256::ecdsa::SigningKey::from_slice(&key32) {
        let psig: p256::ecdsa::Signature = psk.sign(raw);
        let _ = core::hint::black_box(psk.verifying_key().verify(raw, &psig));
    }

    // secp256k1 0.30 + 0.29 sign/verify/recover
    let secp = secp256k1::Secp256k1::new();
    if let Ok(sk) = secp256k1::SecretKey::from_slice(&key32) {
        let msg = secp256k1::Message::from_digest(key32);
        let rsig = secp.sign_ecdsa_recoverable(&msg, &sk);
        let _ = core::hint::black_box(secp.recover_ecdsa(&msg, &rsig));
        let sig = secp.sign_ecdsa(&msg, &sk);
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let _ = core::hint::black_box(secp.verify_ecdsa(&msg, &sig, &pk));
    }
    let secp29 = secp256k1_29::Secp256k1::new();
    if let Ok(sk) = secp256k1_29::SecretKey::from_slice(&key32) {
        let msg = secp256k1_29::Message::from_digest(key32);
        let rsig = secp29.sign_ecdsa_recoverable(&msg, &sk);
        let _ = core::hint::black_box(secp29.recover_ecdsa(&msg, &rsig));
    }

    // ark-ff / ark-ec / ark-bn254 / ark-bls12-381 batch_inversion, serialize/deserialize, sqrt, pow, msm, pairing
    let mut frs = [
        ark_bn254::Fr::from(raw.len() as u64 + 3),
        ark_bn254::Fr::from(raw.len() as u64 + 11),
        ark_bn254::Fr::from(raw.len() as u64 + 19),
    ];
    ark_ff::batch_inversion(&mut frs);
    let _ = core::hint::black_box((frs[0].sqrt(), frs[1].pow([5u64, 7u64]), frs[2].into_bigint().to_bytes_be()));
    let mut sbuf = Vec::new();
    let g1 = ark_bn254::G1Affine::generator();
    let g2 = ark_bn254::G2Affine::generator();
    let _ = g1.serialize_compressed(&mut sbuf);
    let _ = core::hint::black_box(ark_bn254::G1Affine::deserialize_compressed(sbuf.as_slice()));
    let _ = core::hint::black_box((
        ark_bn254::G1Projective::msm(&[g1, g1], &frs[..2]).map(|p| p.into_affine()),
        ark_bn254::G2Projective::msm(&[g2, g2], &frs[..2]).map(|p| p.into_affine()),
        ark_bn254::Bn254::multi_pairing([g1], [g2]),
    ));

    let mut bfrs = [
        ark_bls12_381::Fr::from(raw.len() as u64 + 5),
        ark_bls12_381::Fr::from(raw.len() as u64 + 13),
    ];
    ark_ff::batch_inversion(&mut bfrs);
    let bg1 = ark_bls12_381::G1Affine::generator();
    let bg2 = ark_bls12_381::G2Affine::generator();
    let mut bsbuf = Vec::new();
    let _ = bg1.serialize_compressed(&mut bsbuf);
    let _ = core::hint::black_box(ark_bls12_381::G1Affine::deserialize_compressed(bsbuf.as_slice()));
    let _ = core::hint::black_box((
        ark_bls12_381::G1Projective::msm(&[bg1, bg1], &bfrs).map(|p| p.into_affine()),
        ark_bls12_381::G2Projective::msm(&[bg2, bg2], &bfrs).map(|p| p.into_affine()),
        ark_bls12_381::Bls12_381::multi_pairing([bg1], [bg2]),
    ));

    // sha2 0.9 + 0.10 + hmac + tiny-keccak + curve25519 + c-kzg
    let _ = core::hint::black_box(<sha2::Sha256 as sha2::Digest>::digest(raw));
    let _ = core::hint::black_box(<sha2::Sha512 as sha2::Digest>::digest(raw));
    let _ = core::hint::black_box(sha2_10::Sha256::digest(raw));
    let _ = core::hint::black_box(sha2_10::Sha512::digest(raw));
    if let Ok(mut mac) = hmac::Hmac::<sha2_10::Sha256>::new_from_slice(&key32) {
        mac.update(raw);
        let _ = core::hint::black_box(mac.finalize().into_bytes());
    }
    let mut sha3 = tiny_keccak::Sha3::v256();
    sha3.update(raw);
    let mut out = [0u8; 32];
    sha3.finalize(&mut out);
    let _ = core::hint::black_box(out);
    let sc = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order(key32);
    let pt = &sc * &curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
    let _ = core::hint::black_box((pt.compress().decompress(), pt.to_montgomery()));
    let _ = core::hint::black_box(c_kzg::ethereum_kzg_settings(0));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        touch_alloy_trie_and_sol(&arg);
        touch_crypto_deep(&arg);
    }
}
