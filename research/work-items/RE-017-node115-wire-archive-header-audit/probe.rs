use node115_replay_completed_payload::{CompletedPayload, decode_completed_payload};
use std::{env, fs};

fn main() {
    let path = env::args_os().nth(1).expect("local wire path");
    let wire = fs::read(path).expect("read wire bytes");
    let completed = decode_completed_payload(CompletedPayload::Plain(&wire)).unwrap();
    assert_eq!(completed.consumed, wire.len());
    emit(&completed);
}

#[cfg(project_header)]
fn emit(completed: &node115_replay_completed_payload::DecodedPrefix) {
    let cutoff = env::args().nth(2).expect("ordinary conversion cutoff").parse().unwrap();
    let header = completed.project_replica_header(cutoff).expect("decoded Block header");
    let proposer = header.proposer.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!(
        "{{\"proposer\":\"0x{proposer}\",\"round\":{},\"parent_round\":{},\"hardfork\":{{\"version\":{},\"round\":{}}}}}",
        header.round, header.parent_round, header.hardfork[0], header.hardfork[1],
    );
}

#[cfg(not(project_header))]
fn emit(completed: &node115_replay_completed_payload::DecodedPrefix) {
    println!("{}", completed.render_replica_time().expect("decoded Block clock").as_str());
}
