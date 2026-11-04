use node115_rlp_flag_pair::{DecodeError, FlagPair, Reader};
#[test]
fn frozen_target_grounded_predictions() {
    let text =
        include_str!("../../../research/work-items/RE-005-node115-rlp-flag-pair/predictions.tsv");
    let mut count = 0;
    for line in text
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
    {
        let p: Vec<&str> = line.split('\t').collect();
        assert_eq!(p.len(), 7);
        let input: Vec<u8> = p[1]
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(input.len() * 2, p[1].len());
        let mut reader = Reader::new(&input);
        let result = reader.read_flag_pair();
        if p[2] != "-" {
            assert_eq!(
                result,
                Err(DecodeError {
                    code: p[2].parse().unwrap()
                }),
                "{}",
                p[0]
            );
        } else {
            let limbs = |s: &str| -> [u64; 4] {
                s.split(',')
                    .map(|v| v.parse().unwrap())
                    .collect::<Vec<u64>>()
                    .try_into()
                    .unwrap()
            };
            assert_eq!(
                result,
                Ok(FlagPair {
                    flag: p[4].parse().unwrap(),
                    first: limbs(p[5]),
                    second: limbs(p[6])
                }),
                "{}",
                p[0]
            );
        }
        assert_eq!(
            reader.consumed(),
            p[3].parse::<usize>().unwrap(),
            "{}",
            p[0]
        );
        count += 1;
    }
    assert_eq!(count, 20);
}
