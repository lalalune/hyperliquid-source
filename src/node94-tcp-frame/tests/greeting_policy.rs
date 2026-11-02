#![cfg(feature = "timed-stream")]

use node94_tcp_frame::greeting::Request;
use node94_tcp_frame::greeting::policy::{PeerRejection, Route};
use node94_tcp_frame::greeting::reply::{FixedRecord, HashReply, Map, MapValue, Reply};

// Rows follow the native dispatch projection: outer 0/hash 0, 1, 2; outer 1..5.
// Expected outcomes come from RE-012-greeting-policy-94/CONTRACT.md.
const ZERO: [Result<Route, PeerRejection>; 8] = [
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::NoQuorumL1Hash),
    Ok(Route::ContinueStream),
    Err(PeerRejection::Full),
    Err(PeerRejection::RateLimited),
];

const NONZERO_EVEN: [Result<Route, PeerRejection>; 8] = [
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::NoQuorumL1Hash),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::Full),
    Err(PeerRejection::RateLimited),
];

const ODD: [Result<Route, PeerRejection>; 8] = [
    Ok(Route::ValidateState),
    Ok(Route::ValidateState),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::NoQuorumL1Hash),
    Err(PeerRejection::InconsistentGreeting),
    Err(PeerRejection::Full),
    Err(PeerRejection::RateLimited),
];

fn request(first: u8, second: u8, time_header: bool) -> Request {
    Request {
        first,
        second,
        time_header,
    }
}

fn variants(seed: u8) -> [Reply; 8] {
    let mut map = Map::new();
    if seed != 0 {
        map.insert(
            [seed; 20],
            MapValue {
                first: [u64::MAX, 0, 250, 251],
                second: [1, 1 << 63, 65_536, u32::MAX as u64],
                last: seed,
            },
        );
    }
    let bytes = vec![seed; usize::from(seed)];
    let word = if seed == 0 { 0 } else { u64::MAX };
    [
        Reply::Variant0 {
            bytes: bytes.clone(),
            word,
            hash: HashReply::Variant0 {
                bytes: [seed; 32],
                map: map.clone(),
            },
        },
        Reply::Variant0 {
            bytes: bytes.clone(),
            word,
            hash: HashReply::Variant1 {
                bytes: [seed; 32],
                first: map.clone(),
                second: map,
            },
        },
        Reply::Variant0 {
            bytes,
            word,
            hash: HashReply::Variant2(Box::new(core::array::from_fn(|index| FixedRecord {
                first: word.wrapping_add(index as u64),
                second: word.wrapping_sub(index as u64),
                bytes: [seed.wrapping_add(index as u8); 2048],
            }))),
        },
        Reply::Variant1([word, 1 << 63, u64::from(seed)]),
        Reply::Variant2,
        Reply::Variant3,
        Reply::Variant4,
        Reply::Variant5,
    ]
}

#[test]
fn all_raw_flag_bytes_and_all_eight_logical_variants_match_the_native_table() {
    let replies = variants(0);
    for first in 0..=u8::MAX {
        let expected = if first == 0 {
            ZERO
        } else if first % 2 == 0 {
            NONZERO_EVEN
        } else {
            ODD
        };
        for (index, reply) in replies.iter().enumerate() {
            assert_eq!(
                request(first, 0, false).route_reply(reply),
                expected[index],
                "first={first}, logical variant={index}"
            );
        }
    }
}

#[test]
fn second_request_byte_and_header_timing_do_not_affect_routing() {
    let replies = variants(0);
    for first in 0..=u8::MAX {
        for reply in &replies {
            let expected = request(first, 0, false).route_reply(reply);
            for second in 0..=u8::MAX {
                for time_header in [false, true] {
                    assert_eq!(
                        request(first, second, time_header).route_reply(reply),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn reply_payload_fields_do_not_select_the_route() {
    let baseline = variants(0);
    let different_fields = variants(255);
    for first in 0..=u8::MAX {
        for (left, right) in baseline.iter().zip(&different_fields) {
            let req = request(first, 128, true);
            assert_eq!(req.route_reply(left), req.route_reply(right));
        }
    }
}

#[test]
fn raw_flags_distinguish_zero_nonzero_even_and_odd() {
    let replies = variants(0);
    for first in [2, 128, 254] {
        assert_eq!(
            request(first, 0, false).route_reply(&replies[0]),
            Err(PeerRejection::InconsistentGreeting)
        );
        assert_eq!(
            request(first, 0, false).route_reply(&replies[5]),
            Err(PeerRejection::InconsistentGreeting)
        );
    }
    for first in [1, 3, 255] {
        assert_eq!(
            request(first, 0, false).route_reply(&replies[0]),
            Ok(Route::ValidateState)
        );
        assert_eq!(
            request(first, 0, false).route_reply(&replies[5]),
            Err(PeerRejection::InconsistentGreeting)
        );
    }
    assert_eq!(
        request(0, 0, false).route_reply(&replies[5]),
        Ok(Route::ContinueStream)
    );
}

#[test]
fn rejection_text_matches_the_target_formatter_without_native_tag_claims() {
    use std::error::Error;

    for (error, text) in [
        (PeerRejection::Full, "Peer full"),
        (PeerRejection::RateLimited, "Rate limited by peer"),
        (PeerRejection::NoQuorumL1Hash, "Peer no quorum l1 hash"),
        (
            PeerRejection::InconsistentGreeting,
            "Peer inconsistent greeting",
        ),
    ] {
        assert_eq!(error.to_string(), text);
        assert!(error.source().is_none());
    }
}
