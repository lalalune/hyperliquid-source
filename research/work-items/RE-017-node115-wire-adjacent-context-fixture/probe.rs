use node115_replay_completed_payload::{
    CompletedPayload, ReplayBlockCheck, decode_completed_payload,
};
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let terms: Vec<u64> = std::env::args()
        .skip(1)
        .map(|arg| arg.parse().expect("unsigned fixture word"))
        .collect();
    let [cutoff, first, second] = terms[..] else {
        panic!("expected cutoff and ordered identity words")
    };
    let decoded = decode_completed_payload(CompletedPayload::Plain(&input)).unwrap();
    assert_eq!(
        decoded.consumed,
        input.len(),
        "wire fixture must be the complete prefix"
    );
    let header = decoded
        .project_replica_header(cutoff)
        .expect("ordinary decoded Block");
    assert_eq!(
        decoded.check_block_identity([first, second]),
        ReplayBlockCheck::Match {
            successor: header.round
        },
    );
    println!(
        "{{\"round\":{},\"parent_round\":{},\"date_word\":{},\"seconds\":{},\"nanos\":{}}}",
        header.round,
        header.parent_round,
        header.time.packed_date,
        header.time.second_of_day,
        header.time.nanoseconds,
    );
    Ok(())
}
