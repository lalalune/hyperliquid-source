use node115_client_block_success::{Parent, replay_parent_projection};
use node115_replay_completed_payload::{
    CompletedPayload, ReplayPayload,
    conversion::{ConversionCursor, ConversionOutcome, PreparedRecord},
    decode_completed_payload,
};
use std::{env, fs};

fn main() {
    let mut args = env::args().skip(1);
    let restored = args.next().expect("restored round").parse().unwrap();
    let mut cursor = ConversionCursor::from_restored_round(restored);
    let mut rows = Vec::new();
    while let Some(path) = args.next() {
        let count = args
            .next()
            .expect("observed prepared attachment count")
            .parse()
            .unwrap();
        rows.push((path, count));
    }
    for (index, (path, attachment_count)) in rows.into_iter().enumerate() {
        let wire = fs::read(path).expect("prepared replay record path");
        let decoded = decode_completed_payload(CompletedPayload::Plain(&wire)).unwrap();
        assert_eq!(decoded.consumed, wire.len());
        let ReplayPayload::Block { block, .. } = decoded.result.expect("ordinary decoded record")
        else {
            panic!("expected Block in the ordered fixture");
        };
        let Parent::QuorumCertificate(qc) = &block.header.parent else {
            panic!("ordinary direct quorum fixture required");
        };
        let identity = qc.fields[2];
        let successor = replay_parent_projection(&block.header.parent).successor;
        let (event, parent_round) = match cursor.observe(PreparedRecord {
            identity,
            successor,
            attachment_count,
        }) {
            ConversionOutcome::IdentityMismatch { .. } => ("identity_mismatch", "null".to_owned()),
            ConversionOutcome::EmptyRecordSkipped => ("skipped", "null".to_owned()),
            ConversionOutcome::Converted { parent_round } => {
                ("converted", parent_round.to_string())
            }
        };
        println!(
            "{{\"index\":{index},\"identity\":{identity},\"successor\":{successor},\"prepared_count\":{attachment_count},\"outcome\":\"{event}\",\"parent_round\":{parent_round},\"expected_after\":{},\"cutoff_after\":{}}}",
            cursor.expected_identity(),
            cursor.cutoff(),
        );
        if event != "skipped" {
            break;
        }
    }
}
