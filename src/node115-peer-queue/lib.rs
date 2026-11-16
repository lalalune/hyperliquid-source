//! Logical continuation of the selected Peers response. Native container
//! allocation, tree iteration, scheduler, and queue sharing are premises.
use node115_peers_response_set::{decode_frame, Decoded, Error, PeerSet};
use std::collections::VecDeque;

/// Append selected four-byte keys in normalized set order. Existing entries
/// remain in front; no cross-response deduplication is performed.
pub fn append_selected(queue: &mut VecDeque<[u8; 4]>, set: &PeerSet) -> usize {
    let before = queue.len();
    queue.extend(set.peers().iter().filter(|row| row.flag).map(|row| row.key));
    queue.len() - before
}

/// Decode one selected response and append its keys only after decode succeeds.
/// This API does not model the captured future, error ABI, or stream ownership.
pub fn decode_and_append<'a>(
    queue: &mut VecDeque<[u8; 4]>,
    frame: &'a [u8],
) -> Result<(Decoded, &'a [u8]), Error> {
    let (decoded, rest) = decode_frame(frame)?;
    append_selected(queue, &decoded.set);
    Ok((decoded, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sorted_last_winner_and_existing_queue() {
        let bytes = [
            0, 0, 0, 23, 0, 1, 3, 0, 1, 2, 3, 4, 0, 1, 0, 0, 0, 0, 1, 1, 2, 0, 1, 2, 3, 4, 1, 3,
        ];
        let mut q = VecDeque::from([[9, 9, 9, 9]]);
        let (d, rest) = decode_and_append(&mut q, &bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(d.wire_rows, 3);
        assert_eq!(
            q.into_iter().collect::<Vec<_>>(),
            vec![[9, 9, 9, 9], [0, 0, 0, 1], [1, 2, 3, 4]]
        );
    }
    #[test]
    fn false_row_is_not_queued_and_error_does_not_modify_queue() {
        let bytes = [
            0, 0, 0, 18, 0, 1, 2, 0, 0x52, 0xa7, 0x4c, 0x25, 0, 250, 0, 0x97, 0xba, 0xa9, 0x3e, 1,
            251, 251, 0,
        ];
        let mut q = VecDeque::from([[1, 2, 3, 4]]);
        decode_and_append(&mut q, &bytes).unwrap();
        assert_eq!(q, VecDeque::from([[1, 2, 3, 4], [0x97, 0xba, 0xa9, 0x3e]]));
        let saved = q.clone();
        assert!(decode_and_append(&mut q, &[0, 0, 0, 5, 0, 1]).is_err());
        assert_eq!(q, saved);
    }
    #[test]
    fn prior_frozen_wire_corpus_selects_expected_keys() {
        let corpus = include_str!("../node115-peers-response-set/tests/corpus.tsv");
        let mut success = 0;
        let mut errors = 0;
        for line in corpus
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
        {
            let mut cols = line.split('\t');
            let id = cols.next().unwrap();
            let hex = cols.next().unwrap();
            let expected = cols.next().unwrap();
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>();
            let mut queue = VecDeque::from([[0xaa, 0xbb, 0xcc, 0xdd]]);
            let result = decode_and_append(&mut queue, &bytes);
            if !expected.starts_with("ok;") {
                assert!(result.is_err(), "{id}");
                assert_eq!(queue, VecDeque::from([[0xaa, 0xbb, 0xcc, 0xdd]]), "{id}");
                errors += 1;
                continue;
            }
            result.unwrap();
            let rows = expected
                .split(';')
                .find_map(|x| x.strip_prefix("rows="))
                .unwrap();
            let mut wanted = vec![[0xaa, 0xbb, 0xcc, 0xdd]];
            for row in rows.split(',').filter(|s| !s.is_empty()) {
                let mut fields = row.split(':');
                let key = fields.next().unwrap();
                if fields.next().unwrap() == "1" {
                    let mut bytes = [0; 4];
                    for (i, b) in bytes.iter_mut().enumerate() {
                        *b = u8::from_str_radix(&key[i * 2..i * 2 + 2], 16).unwrap();
                    }
                    wanted.push(bytes);
                }
            }
            assert_eq!(queue.into_iter().collect::<Vec<_>>(), wanted, "{id}");
            success += 1;
        }
        assert_eq!((success, errors), (195, 34));
    }
    #[test]
    fn wrapped_existing_queue_and_successive_responses_keep_duplicates() {
        let frame = [0, 0, 0, 9, 0, 1, 1, 0, 9, 9, 9, 9, 1, 7];
        let mut q = VecDeque::with_capacity(8);
        for x in 0..8 {
            q.push_back([x, 0, 0, 0]);
        }
        for _ in 0..6 {
            q.pop_front();
        }
        q.push_back([8, 0, 0, 0]);
        q.push_back([9, 0, 0, 0]);
        assert!(!q.as_slices().1.is_empty());
        decode_and_append(&mut q, &frame).unwrap();
        decode_and_append(&mut q, &frame).unwrap();
        assert_eq!(
            q.into_iter().collect::<Vec<_>>(),
            vec![
                [6, 0, 0, 0],
                [7, 0, 0, 0],
                [8, 0, 0, 0],
                [9, 0, 0, 0],
                [9, 9, 9, 9],
                [9, 9, 9, 9]
            ]
        );
    }
}
