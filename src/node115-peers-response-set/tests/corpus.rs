//! Runs every case of the frozen oracle corpus (tests/corpus.tsv, produced by
//! research/work-items/RE-012-node115-peers-response-set/oracle/gen_oracle.py
//! before this crate existed) through the public API.
use std::io::ErrorKind;

use node115_peers_response_set::address_vector::Error as RowError;
use node115_peers_response_set::{
    decode_frame, outer, Error, FrameErrorKind, ReadStage, ResponseError, Storage,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn class(e: &Error) -> &'static str {
    match e {
        Error::NoFrame => "eof",
        Error::Frame(f) => match f.kind {
            FrameErrorKind::OverLimit(_) => "over_limit",
            FrameErrorKind::Lz4(_) => "lz4",
            FrameErrorKind::Io { stage: ReadStage::Header, kind: ErrorKind::UnexpectedEof } => "frame_header",
            FrameErrorKind::Io { stage: ReadStage::Payload, kind: ErrorKind::UnexpectedEof } => "frame_payload",
            _ => "frame_other",
        },
        Error::NotPeers(_) => "not_peers",
        Error::Response(ResponseError::Outer(o)) => match o {
            outer::Error::Read(outer::ReadError::UnexpectedEnd { .. }) => "short_input",
            outer::Error::Read(outer::ReadError::Limit) => "limit",
            outer::Error::Read(outer::ReadError::Invalid { .. }) | outer::Error::InvalidVariant { .. } => "outer_tag",
            _ => "outer_other",
        },
        Error::Response(ResponseError::Addresses(a)) => match a {
            RowError::Read(outer::ReadError::UnexpectedEnd { .. }) => "short_input",
            RowError::Read(outer::ReadError::Limit) => "limit",
            RowError::Read(outer::ReadError::Invalid { .. }) => "bad_scalar",
            RowError::InvalidVariant(_) => "bad_node_tag",
            RowError::InvalidBool => "bad_bool",
            RowError::Refund | RowError::Allocation => "internal",
        },
        Error::Response(_) => "other_response_error",
    }
}

fn field<'a>(fields: &'a [&'a str], name: &str) -> &'a str {
    let prefix = format!("{name}=");
    fields
        .iter()
        .find_map(|f| f.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("missing field {name}"))
}

#[test]
fn every_corpus_case_matches_the_oracle() {
    let text = include_str!("corpus.tsv");
    let mut cases = 0;
    let mut ok_cases = 0;
    let mut big_trees = 0;
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let parts: Vec<&str> = line.split('\t').collect();
        assert_eq!(parts.len(), 3, "{line:.60}");
        let (id, frame, expect) = (parts[0], unhex(parts[1]), parts[2]);
        let fields: Vec<&str> = expect.split(';').collect();
        let got = decode_frame(&frame);
        cases += 1;
        if fields[0] == "err" {
            let e = got.as_ref().err().unwrap_or_else(|| panic!("{id}: expected an error"));
            assert_eq!(class(e), field(&fields, "class"), "{id}: {e:?}");
            continue;
        }
        ok_cases += 1;
        let (decoded, rest) = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let set = &decoded.set;
        let storage = match set.storage() {
            Storage::Small => "small",
            Storage::Tree => "tree",
        };
        assert_eq!(storage, field(&fields, "storage"), "{id}");
        if set.storage() == Storage::Tree {
            big_trees += 1;
        }
        assert_eq!(decoded.compressed as u8, field(&fields, "compressed").parse().unwrap(), "{id}");
        assert_eq!(decoded.wire_rows, field(&fields, "wire").parse::<usize>().unwrap(), "{id}");
        assert_eq!(set.len(), field(&fields, "kept").parse::<usize>().unwrap(), "{id}");
        assert_eq!(decoded.charged, field(&fields, "charged").parse::<u64>().unwrap(), "{id}");
        assert_eq!(decoded.payload_remaining, field(&fields, "remaining").parse::<usize>().unwrap(), "{id}");
        assert_eq!(rest.len(), field(&fields, "stream_rest").parse::<usize>().unwrap(), "{id}");
        let rows: Vec<String> = set
            .peers()
            .iter()
            .map(|p| {
                let key: String = p.key.iter().map(|b| format!("{b:02x}")).collect();
                format!("{key}:{}:{}", p.flag as u8, p.value)
            })
            .collect();
        assert_eq!(rows.join(","), field(&fields, "rows"), "{id}");
        let winners: Vec<String> = (0..set.len()).map(|i| set.source_index(i).to_string()).collect();
        assert_eq!(winners.join(","), field(&fields, "winners"), "{id}");
    }
    assert_eq!(cases, 229);
    assert!(ok_cases > 150 && big_trees >= 10, "{ok_cases} ok, {big_trees} trees");
}
