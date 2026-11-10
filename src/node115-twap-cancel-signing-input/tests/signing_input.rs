//! Tests against the frozen independent oracle (`tests/oracle/corpus.tsv`) and
//! hand-typed facts. The corpus was generated and hashed before this crate's
//! source existed (see ORACLE_FROZEN.txt in the evidence packet).

use node115_twap_cancel_signing_input::{
    keccak256_short, preimage, signing_input, tag_for_selector, Cancel, Suffix, RATE,
};

const CORPUS: &str = include_str!("oracle/corpus.tsv");
const CORPUS_ROWS: usize = 665;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

struct Row {
    class: String,
    cancel: Cancel,
    suffix: Suffix,
    selector: u32,
    input: Vec<u8>,
    digest: Vec<u8>,
    tag: u8,
    record: Vec<u8>,
}

fn rows() -> Vec<Row> {
    CORPUS
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 11, "bad corpus row: {line}");
            let vault = if f[4] == "-" {
                None
            } else {
                Some(<[u8; 20]>::try_from(unhex(f[4])).unwrap())
            };
            let expiry = if f[5] == "-" { None } else { Some(f[5].parse().unwrap()) };
            Row {
                class: f[0].to_string(),
                cancel: Cancel {
                    asset: f[1].parse().unwrap(),
                    twap_id: f[2].parse().unwrap(),
                },
                suffix: Suffix {
                    nonce: u64::from_str_radix(f[3], 16).unwrap(),
                    vault,
                    expires_after: expiry,
                },
                selector: f[6].parse().unwrap(),
                input: unhex(f[7]),
                digest: unhex(f[8]),
                tag: unhex(f[9])[0],
                record: unhex(f[10]),
            }
        })
        .collect()
}

#[test]
fn corpus_denominator_and_classes() {
    let all = rows();
    assert_eq!(all.len(), CORPUS_ROWS);
    for class in [
        "anchor", "int-grid", "suffix-combo", "selector", "nonce", "nonce-byte", "vault-byte",
        "vault-zero", "expiry", "single-change", "random",
    ] {
        assert!(all.iter().any(|r| r.class == class), "missing class {class}");
    }
}

#[test]
fn preimage_matches_oracle() {
    for row in rows() {
        let got = preimage(row.cancel, row.suffix);
        assert_eq!(got.as_bytes(), &row.input[..], "{} {:?}", row.class, row.cancel);
    }
}

#[test]
fn digest_matches_oracle() {
    for row in rows() {
        let got = signing_input(row.cancel, row.suffix, row.selector);
        assert_eq!(&got.digest[..], &row.digest[..], "{} {:?}", row.class, row.cancel);
    }
}

#[test]
fn tag_matches_oracle() {
    for row in rows() {
        assert_eq!(signing_input(row.cancel, row.suffix, row.selector).tag, row.tag);
        assert_eq!(tag_for_selector(row.selector), row.tag);
    }
}

#[test]
fn returned_record_matches_oracle() {
    // The oracle leaves the tag-pointer word (bytes 8..16) zero; fill it in here so
    // a pointer written to the wrong slot cannot hide behind a zero address.
    let address = 0x1122_3344_5566_7788u64;
    for row in rows() {
        let out = signing_input(row.cancel, row.suffix, row.selector);
        let bytes: Vec<u8> = out
            .record_words(address)
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let mut want = row.record.clone();
        want[8..16].copy_from_slice(&address.to_le_bytes());
        assert_eq!(bytes, want, "{} {:?}", row.class, row.cancel);
    }
}

#[test]
fn anchor_literals_typed_by_hand() {
    let cancel = Cancel { asset: 1, twap_id: 2 };
    let suffix = Suffix { nonce: 0x0102030405060708, vault: None, expires_after: None };
    let p = preimage(cancel, suffix);
    assert_eq!(
        p.as_bytes(),
        &unhex("83a474797065aa7477617043616e63656ca16101a17402010203040506070800")[..]
    );
    let out = signing_input(cancel, suffix, 3);
    assert_eq!(
        out.digest.to_vec(),
        unhex("5f07dac3d5e01782799cf9f3260ae8ce3d00107075fbef13fae3266c6abf38de")
    );
    assert_eq!(out.tag, 0x61);
    let words = out.record_words(0xdead_beef);
    assert_eq!((words[0], words[1], words[2], words[7]), (1, 0xdead_beef, 1, 0x539));
    assert_eq!(&words[8..], &[0, 0, 0]);
}

#[test]
fn keccak_public_vectors_and_block_limit() {
    for (msg, want) in [
        (&b""[..], "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
        ),
    ] {
        assert_eq!(keccak256_short(msg).unwrap().to_vec(), unhex(want));
    }
    assert!(keccak256_short(&[0u8; RATE - 1]).is_some());
    assert!(keccak256_short(&[0u8; RATE]).is_none());
}

#[test]
fn preimage_length_classes() {
    let nonce = 1;
    let vault = Some([7u8; 20]);
    for (vault, expiry, extra) in [(None, None, 9), (None, Some(5), 18), (vault, None, 29), (vault, Some(5), 38)] {
        let with = preimage(
            Cancel { asset: 1, twap_id: 2 },
            Suffix { nonce, vault, expires_after: expiry },
        );
        let bare = 23; // fixmap + type/twapCancel + a/1 + t/2
        assert_eq!(with.as_bytes().len(), bare + extra);
    }
    let longest = preimage(
        Cancel { asset: u32::MAX, twap_id: u64::MAX },
        Suffix { nonce: u64::MAX, vault, expires_after: Some(u64::MAX) },
    );
    assert_eq!(longest.as_bytes().len(), 73);
}

#[test]
fn present_and_zero_fields_differ_from_absent() {
    let cancel = Cancel { asset: 3, twap_id: 4 };
    let base = Suffix { nonce: 9, vault: None, expires_after: None };
    let zero_vault = Suffix { vault: Some([0; 20]), ..base };
    let zero_expiry = Suffix { expires_after: Some(0), ..base };
    let d = |s| signing_input(cancel, s, 3).digest;
    assert_ne!(d(base), d(zero_vault));
    assert_ne!(d(base), d(zero_expiry));
    assert_ne!(d(zero_vault), d(zero_expiry));
}

#[test]
fn selector_uses_low_byte_only() {
    for selector in [3u32, 0x103, 0x203, 0xffff_ff03] {
        assert_eq!(tag_for_selector(selector), 0x61, "{selector:#x}");
    }
    for selector in [0u32, 1, 2, 4, 0x100, 0x300_0000, u32::MAX] {
        assert_eq!(tag_for_selector(selector), 0x62, "{selector:#x}");
    }
}

/// Agreement with the older `twapCancel` model, whose evidence is the other
/// writer copy (`0x46ac020`). Both models are source code; this is a consistency
/// check between two readings of two writer copies, not a target execution.
#[test]
fn map_prefix_agrees_with_existing_action_wire_crate() {
    use twap_action_wire::{cancel, Cancel as WireCancel, Mode};
    let assets = [0u32, 1, 127, 128, 255, 256, 65535, 65536, 0x7fff_ffff, 0x8000_0000, u32::MAX];
    let ids = [0u64, 1, 127, 128, 255, 256, 65535, 65536, u64::from(u32::MAX), 1 << 32, 1 << 63, u64::MAX];
    let mut checked = 0;
    for asset in assets {
        for twap_id in ids {
            let wire = cancel(WireCancel { asset, t: twap_id }, Mode::Map).unwrap();
            let ours = preimage(
                Cancel { asset, twap_id },
                Suffix { nonce: 0, vault: None, expires_after: None },
            );
            assert_eq!(&ours.as_bytes()[..wire.len()], &wire[..], "{asset} {twap_id}");
            assert_eq!(ours.as_bytes().len(), wire.len() + 9);
            checked += 1;
        }
    }
    assert_eq!(checked, 132);
}
