//! Hand-written cases that do not depend on the generated corpus.
use std::io::Read;

use node115_gossip_response_composed::AddressRecord;
use node115_peers_response_set::{
    decode_frame, decode_stream, normalize, Error, Peer, Storage,
};

fn rec(key: [u8; 4], flag: bool, value: u64) -> AddressRecord {
    AddressRecord { fixed: u64::from(u32::from_le_bytes(key)), value, flag }
}

#[test]
fn scout_frame_gives_two_rows_in_byte_order_and_charge_51() {
    // 28 bytes: header (length 23, flag 0), tag 1, count 3 and three rows.
    let frame = [
        0, 0, 0, 0x17, 0, 1, 3, 0, 1, 2, 3, 4, 0, 1, 0, 0, 0, 0, 1, 1, 2, 0, 1, 2, 3, 4, 1, 3,
    ];
    let (d, rest) = decode_frame(&frame).unwrap();
    assert!(rest.is_empty() && !d.compressed);
    assert_eq!((d.wire_rows, d.charged, d.payload_remaining), (3, 51, 0));
    assert_eq!(
        d.set.peers(),
        &[
            Peer { key: [0, 0, 0, 1], flag: true, value: 2 },
            Peer { key: [1, 2, 3, 4], flag: true, value: 3 },
        ]
    );
    // The later of the two equal-key rows survives; the earlier one is gone.
    assert_eq!((d.set.source_index(0), d.set.source_index(1)), (1, 2));
}

#[test]
fn key_order_is_byte_order_not_little_endian_number_order() {
    let set = normalize(&[rec([1, 0, 0, 0], false, 1), rec([0, 0, 0, 1], false, 2)]);
    assert_eq!(set.peers()[0].key, [0, 0, 0, 1]);
}

#[test]
fn replacement_and_storage_follow_the_thresholds() {
    for (n, kept) in [(20usize, 1usize), (21, 1), (64, 64), (65, 65), (129, 65)] {
        assert!(n >= kept);
        let rows: Vec<_> = (0..n)
            .map(|i| rec([(i % kept) as u8, 0, 0, 0], false, i as u64))
            .collect();
        let set = normalize(&rows);
        assert_eq!(set.len(), kept);
        assert_eq!(
            set.storage(),
            if kept <= 64 { Storage::Small } else { Storage::Tree }
        );
        // every key keeps its last input row, for lengths on both sides of 20
        for (i, p) in set.peers().iter().enumerate() {
            let last = (0..n).filter(|r| r % kept == p.key[0] as usize).last().unwrap();
            assert_eq!(set.source_index(i), last, "n={n}");
        }
    }
}

struct OneByte<'a>(&'a [u8]);
impl Read for OneByte<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.len().min(1).min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

#[test]
fn byte_at_a_time_stream_gives_the_same_result() {
    let frame = [0, 0, 0, 0x0c, 0, 1, 1, 0, 9, 9, 9, 9, 1, 250, 7, 7, 7];
    let whole = decode_frame(&frame).unwrap().0;
    let piecewise = decode_stream(&mut OneByte(&frame)).unwrap();
    assert_eq!(whole, piecewise);
    assert_eq!(whole.payload_remaining, 3);
}

#[test]
fn empty_stream_is_no_frame() {
    assert_eq!(decode_frame(&[]).unwrap_err(), Error::NoFrame);
}
