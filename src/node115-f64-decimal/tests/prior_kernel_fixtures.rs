//! Retained is64=1/round=1 observations from the prior packet's kernel_cases.tsv.
//! One out-of-domain exponent (1088) is deliberately excluded.
use node115_f64_decimal::from_binary_parts;
#[test]
fn retained_kernel_observations_match() {
    let mut count = 0;
    for line in include_str!("prior_kernel_fixtures.tsv").lines().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        let coefficient = fields[0].parse::<u128>().unwrap();
        let exponent = fields[1].parse::<i32>().unwrap();
        let negative = fields[2] == "1";
        let actual = from_binary_parts(coefficient, exponent, negative);
        if fields[3] == "refused" {
            assert_eq!(actual, None, "case {count}");
        } else {
            let flags = u32::from_str_radix(fields[4].trim_start_matches("0x"), 16).unwrap();
            let high = fields[5].parse::<u32>().unwrap();
            let lowmid = fields[6].parse::<u64>().unwrap();
            let expected = [flags, high, lowmid as u32, (lowmid >> 32) as u32];
            assert_eq!(actual.unwrap().words(), expected, "case {count}");
        }
        count += 1;
    }
    assert_eq!(count, 415);
}
