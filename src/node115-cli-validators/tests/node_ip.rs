use node115_cli_validators::validate_node_ip;

#[test]
fn callback_matches_frozen_ipv4_results() {
    let replay = include_str!(
        "../../../research/work-items/node-runtime-cli-value-parsers-115/replay-sample.tsv"
    );
    let mut counts = (0, 0);
    for row in replay.lines().filter(|line| line.starts_with("ip\t")) {
        let fields: Vec<_> = row.split('\t').collect();
        let [_, hex, expected, replayed, "1"] = fields.as_slice() else {
            panic!("unexpected evidence row: {row}");
        };
        assert_eq!(expected, replayed);
        assert_eq!(hex.len() % 2, 0);
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let want = match *replayed {
            "ok" => {
                counts.0 += 1;
                Ok(())
            }
            "err/ip" => {
                counts.1 += 1;
                Err("NodeIpParseError")
            }
            other => panic!("unexpected IPv4 outcome {other}"),
        };
        assert_eq!(validate_node_ip(&bytes), want, "input hex {hex}");
    }
    assert_eq!(counts, (19, 81));
}

#[test]
fn cli_requires_the_whole_option() {
    let mut cursor: &[u8] = b"1.2.3.4x";
    assert_eq!(
        node115_host_ip_gates::read_ipv4(&mut cursor),
        Some([1, 2, 3, 4])
    );
    assert_eq!(cursor, b"x");
    assert_eq!(validate_node_ip(b"1.2.3.4x"), Err("NodeIpParseError"));
    assert_eq!(validate_node_ip(b"255.255.255.255"), Ok(()));
    assert_eq!(
        validate_node_ip(b"255.255.255.255x"),
        Err("NodeIpParseError")
    );
}
