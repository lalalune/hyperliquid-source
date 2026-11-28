use node115_certificate_caller::{Block, Parent, Timestamp, block_digest, serialize_variant_zero};
use node115_client_block_success::{
    AdmittedTimestamp, Header, Parent as WireParent, ReplayPayload, admit_timestamp,
    decode_replay_payload_prefix, replay_parent_projection, replay_retained_parent_link,
};
use node115_nested_certificate_decision::{Certificate, sigmap::SigMap};
use std::{env, fs, path::Path};

fn decode(path: &Path) -> Header {
    let bytes = fs::read(path).expect("read pinned fixture payload");
    let decoded = decode_replay_payload_prefix(&bytes, 10_000_000);
    assert!(
        decoded.remaining.is_empty(),
        "fixture must be one complete plain payload"
    );
    let ReplayPayload::Block { block, .. } = decoded.result.expect("decoded fixture payload")
    else {
        panic!("expected Block on both sides of retained link");
    };
    block.header
}

fn date_to_timestamp(date: AdmittedTimestamp) -> Timestamp {
    let year = i64::from((date.packed_date as i32) >> 13);
    let ordinal = i64::from((date.packed_date >> 4) & 0x1ff);
    let y = year - 1;
    let ce_day = y * 365 + y.div_euclid(4) - y.div_euclid(100) + y.div_euclid(400) + ordinal;
    let seconds = (ce_day - 719_163) * 86_400 + i64::from(date.second_of_day);
    assert_eq!(admit_timestamp(seconds, date.nanoseconds).unwrap(), date);
    Timestamp {
        seconds,
        nanos: date.nanoseconds,
    }
}

fn canonical_previous(header: Header) -> Block {
    let WireParent::QuorumCertificate(qc) = header.parent else {
        panic!("previous fixture requires a direct quorum");
    };
    assert!(
        qc.votes.is_empty(),
        "previous fixture requires an empty vote list"
    );
    let [first, second, f30, f38, f40] = qc.fields;
    Block {
        address: header.address,
        hashes: header.hashes,
        timestamp: date_to_timestamp(header.timestamp),
        parent: Parent::Simple(Certificate {
            sigs: SigMap::empty_ring(),
            pair: [first, second],
            f30,
            f38,
            f40,
            hash: qc.hash,
        }),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let mut args = env::args_os().skip(1);
    let previous = decode(Path::new(&args.next().expect("previous wire fixture")));
    let next = decode(Path::new(&args.next().expect("next wire fixture")));
    let expected_identity = replay_parent_projection(&previous.parent).successor;
    let observed = replay_retained_parent_link(&next.parent);
    let normalized = canonical_previous(previous);
    let canonical = serialize_variant_zero(&normalized);
    let digest = block_digest(&normalized);
    println!(
        "{{\"expected_identity\":{expected_identity},\"observed_identity\":{},\"previous_variant_zero\":\"{}\",\"expected_predecessor\":\"{}\",\"observed_predecessor\":\"{}\",\"link_matches\":{}}}",
        observed.identity,
        hex(&canonical),
        hex(&digest),
        hex(&observed.predecessor),
        expected_identity == observed.identity && digest == observed.predecessor,
    );
}
