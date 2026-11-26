use node115_consensus_batch_floor::{
    Block, Hash, Input, Known, Output, collect, first_resolved_floor,
};
fn hash(n: u8) -> Hash {
    let mut h = [0; 32];
    h[31] = n;
    h
}
fn block(tag: usize, round: u64) -> Block {
    Block {
        tag18_is_min_plus_one: tag == 0,
        taga8_is_min_plus_one: tag == 1,
        round50: round,
        rounda0: round,
        round48: round,
        roundd8: round,
    }
}
#[test]
fn boundary_table_preserves_effect_order_and_empty_certificates() {
    let rounds = [0, 3, u64::MAX - 1, u64::MAX];
    let floors = [0, 1, 4, 5, u64::MAX];
    // Rows correspond to rounds; columns to floors. These expectations include
    // equality and saturation, independent of the implementation's arithmetic.
    let admitted = [
        [true, true, false, false, false],
        [true, true, true, false, false],
        [true, true, true, true, true],
        [true, true, true, true, true],
    ];
    for (ri, r) in rounds.into_iter().enumerate() {
        for (fi, f) in floors.into_iter().enumerate() {
            for known_flag in [false, true] {
                for verified in [false, true] {
                    for certificates in [None, Some(Vec::<u8>::new()), Some(vec![11])] {
                        let known = Known::Tree(if known_flag {
                            [(hash(1), block(2, 17))].into_iter().collect()
                        } else {
                            Default::default()
                        });
                        let expected_call = !known_flag && admitted[ri][fi];
                        let expected_emit =
                            certificates.is_some() && (known_flag || expected_call && verified);
                        let mut calls = 0;
                        let result = collect(
                            [Input {
                                hash: hash(1),
                                block: block(0, r),
                                certificates: certificates.clone(),
                            }],
                            &known,
                            f,
                            |_| {
                                calls += 1;
                                verified
                            },
                        );
                        assert_eq!(calls, usize::from(expected_call));
                        assert_eq!(result.len(), usize::from(expected_emit));
                        if expected_emit {
                            assert_eq!(result[0].certificates, certificates.unwrap());
                            assert_eq!(
                                result[0].block,
                                if known_flag { None } else { Some(block(0, r)) }
                            );
                            assert_eq!(
                                first_resolved_floor(&result, &known),
                                Some(if known_flag { 17 } else { r })
                            );
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn map_rotation_and_missing_elided_prefix_match_linear_minimum() {
    let rows = [
        (hash(1), block(0, u64::MAX)),
        (hash(3), block(1, 5)),
        (hash(7), block(2, 0)),
    ];
    for head in 0..5 {
        let mut physical = vec![(hash(255), block(0, 0)); 5];
        for (i, row) in rows.iter().enumerate() {
            physical[(head + i) % 5] = row.clone();
        }
        for known in [
            Known::Tree(rows.iter().cloned().collect()),
            Known::ring(physical, head, 3).unwrap(),
        ] {
            for n in 0..=255 {
                assert_eq!(
                    known.get(&hash(n)),
                    rows.iter().find(|(h, _)| *h == hash(n)).map(|(_, b)| b)
                );
            }
            let mut outputs: Vec<Output<()>> = vec![Output {
                hash: hash(255),
                block: None,
                certificates: (),
            }];
            assert_eq!(first_resolved_floor(&outputs, &known), None);
            for (h, expected) in [(1, u64::MAX), (3, 5), (7, 0)] {
                outputs.push(Output {
                    hash: hash(h),
                    block: None,
                    certificates: (),
                });
                assert_eq!(first_resolved_floor(&outputs, &known), Some(expected));
            }
            assert_eq!(first_resolved_floor::<()>(&[], &known), None);
        }
    }
}
#[test]
fn three_way_projection_and_first_resolved_suffix_keep_original_block_order() {
    let mut blocks = Vec::new();
    for tag in 0..3 {
        let mut b = block(tag, 0);
        b.round50 = 41;
        b.rounda0 = 101;
        b.round48 = 19;
        b.roundd8 = 7;
        blocks.push(b);
    }
    let known = Known::Tree(Default::default());
    // All composite batch rounds use a0, even though later floors choose 48/d8.
    let inputs = blocks.iter().cloned().enumerate().map(|(i, b)| Input {
        hash: hash(i as u8),
        block: b,
        certificates: Some(i),
    });
    let result = collect(inputs, &known, 43, |_| true);
    assert_eq!(
        result.iter().map(|x| x.certificates).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(result[0].block, Some(blocks[1].clone()));
    assert_eq!(result[1].block, Some(blocks[2].clone()));
    assert_eq!(first_resolved_floor(&result, &known), Some(7));
}
