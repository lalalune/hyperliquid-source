use node115_replay_completed_payload::{
    CompletedPayload, ReplayPayload, attachments::AttachmentFixtureCheck, decode_completed_payload,
};
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut wire = Vec::new();
    io::stdin().read_to_end(&mut wire)?;
    let decoded = decode_completed_payload(CompletedPayload::Plain(&wire)).unwrap();
    assert_eq!(decoded.consumed, wire.len());
    let AttachmentFixtureCheck::Ready { attachment_count } = decoded.check_attachment_fixture()
    else {
        panic!("decoded owner content and header digests must match");
    };
    let Ok(ReplayPayload::Block { attachments, .. }) = decoded.result else {
        unreachable!()
    };
    assert_eq!(attachments.as_ref().map_or(0, Vec::len), attachment_count);
    for row in attachments.into_iter().flatten() {
        let hash = row
            .hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("0x{hash}");
    }
    Ok(())
}
