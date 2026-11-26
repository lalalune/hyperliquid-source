use node115_u256_decimal_scale::scale_amount;
use std::process::Command;

fn limbs(hex: &str) -> [u64; 4] {
    std::array::from_fn(|i| {
        let end = hex.len() - 16 * i;
        u64::from_str_radix(&hex[end - 16..end], 16).unwrap()
    })
}

#[test]
fn compares_return_and_input_mutation_with_arbitrary_precision() {
    let output = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference.py"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.lines().count() > 4_000);
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let exponent = fields.next().unwrap().parse().unwrap();
        let mut input = limbs(fields.next().unwrap());
        let after = limbs(fields.next().unwrap());
        let expected: i64 = fields.next().unwrap().parse().unwrap();
        assert_eq!(
            scale_amount(&mut input, exponent),
            u64::try_from(expected).ok(),
            "{line}"
        );
        assert_eq!(input, after, "{line}");
    }
}
