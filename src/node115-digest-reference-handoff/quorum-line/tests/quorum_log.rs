use node115_digest_reference_handoff::{ReferenceRow, TrackerProjection};
use node115_quorum_line::quorum_log_line;

#[test]
fn selected_row_matches_the_frozen_witness_file() {
    let row = ReferenceRow {
        height: 41,
        digest: [0x11; 32],
        members: [[0x44; 20]].into(),
    };
    let mut tracker = TrackerProjection {
        ready: vec![row],
        ..Default::default()
    };
    let drained = tracker.drain_ready();
    assert_eq!(drained.len(), 1);
    assert_eq!(
        quorum_log_line(&drained[0]),
        include_str!(
            "../../../../research/work-items/RE-017-next-height-digest-witness-115/fixtures/witness.jsonl"
        )
    );
}

#[test]
fn heights_and_each_digest_lane_have_the_native_text_shape() {
    for height in [0, u64::MAX] {
        let row = ReferenceRow {
            height,
            digest: core::array::from_fn(|i| if i % 2 == 0 { i as u8 } else { 255 - i as u8 }),
            members: Default::default(),
        };
        let digits = "00fe02fc04fa06f808f60af40cf20ef010ee12ec14ea16e818e61ae41ce21ee0";
        assert_eq!(
            quorum_log_line(&row),
            format!("{{\"height\":{height},\"d\":\"0x{digits}\"}}\n")
        );
    }
}
