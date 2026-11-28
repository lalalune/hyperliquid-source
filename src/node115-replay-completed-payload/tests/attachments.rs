use node115_replay_completed_payload::{
    CompletedPayload, DecodedPrefix, attachments::AttachmentFixtureCheck, decode_completed_payload,
};

const EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];
const ABC: [u8; 32] = [
    0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6, 0x67,
    0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45,
];

type Attachment<'a> = ([u8; 32], &'a [u8]);

fn decode_fixture(hashes: &[[u8; 32]], attachments: Option<&[Attachment<'_>]>) -> DecodedPrefix {
    let mut wire = vec![0; 10]; // Block tag and signature placeholder
    wire.extend([0x31; 20]); // proposer
    wire.push(hashes.len().try_into().unwrap());
    for hash in hashes {
        wire.extend(hash);
    }
    wire.extend([0, 7, 0]); // timestamp and quorum parent
    wire.extend([1, 2, 3, 4, 5]); // quorum-certificate fields
    wire.extend([0x71; 32]); // quorum hash
    wire.extend([0, 0]); // empty votes and omitted proof
    if let Some(attachments) = attachments {
        wire.extend([1, attachments.len().try_into().unwrap()]);
        for (hash, bytes) in attachments {
            wire.extend(hash);
            wire.push(bytes.len().try_into().unwrap());
            wire.extend(*bytes);
        }
    } else {
        wire.push(0);
    }
    let decoded = decode_completed_payload(CompletedPayload::Plain(&wire)).unwrap();
    assert_eq!(decoded.consumed, wire.len());
    decoded
}

#[test]
fn decoded_rows_match_known_content_digests_in_block_order() {
    let rows = [(ABC, b"abc".as_slice()), (EMPTY, b"".as_slice())];
    let decoded = decode_fixture(&[ABC, EMPTY], Some(&rows));
    assert_eq!(
        decoded.check_attachment_fixture(),
        AttachmentFixtureCheck::Ready {
            attachment_count: 2
        },
    );
}

#[test]
fn absent_owner_remains_unknown_when_the_block_names_digests() {
    assert_eq!(
        decode_fixture(&[ABC], None).check_attachment_fixture(),
        AttachmentFixtureCheck::MissingOwner { expected: 1 },
    );
    for rows in [None, Some([].as_slice())] {
        assert_eq!(
            decode_fixture(&[], rows).check_attachment_fixture(),
            AttachmentFixtureCheck::Ready {
                attachment_count: 0
            },
        );
    }
}

#[test]
fn valid_attachment_bytes_can_still_disagree_with_block_order_or_count() {
    let rows = [(EMPTY, b"".as_slice()), (ABC, b"abc".as_slice())];
    assert_eq!(
        decode_fixture(&[ABC, EMPTY], Some(&rows)).check_attachment_fixture(),
        AttachmentFixtureCheck::BlockDigestMismatch { position: 0 },
    );
    assert_eq!(
        decode_fixture(&[ABC], Some(&rows)).check_attachment_fixture(),
        AttachmentFixtureCheck::CountMismatch {
            expected: 1,
            observed: 2
        },
    );
}

#[test]
fn decoded_attachment_content_is_compared_before_the_block_vector() {
    let rows = [(ABC, b"abd".as_slice())];
    assert_eq!(
        decode_fixture(&[EMPTY], Some(&rows)).check_attachment_fixture(),
        AttachmentFixtureCheck::ContentDigestMismatch { position: 0 },
    );
}
