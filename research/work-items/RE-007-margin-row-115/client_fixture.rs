// Input-only adapter. No expected data and no alternate margin arithmetic.
fn adapt(input: &str) -> std::string::String {
    let fields: std::vec::Vec<u64> = input.split('\t').map(|s| s.parse().unwrap()).collect();
    assert_eq!(fields.len(), 4);
    let b = NonZeroU8::new(u8::try_from(fields[2]).unwrap()).unwrap();
    let value = match fields[0] {
        0 => first_selected_row(fields[1], b, fields[3]),
        1 => second_selected_row(fields[1], b, fields[3]),
        2 => { assert_eq!(fields[1], 0); post_doubling_point(b, fields[3]) },
        _ => panic!("unsupported point input"),
    };
    match value {
        Observation::Normal(v) => std::format!("V:{v}"),
        Observation::SubtractionDiagnosticBoundary => std::string::String::from("B"),
        Observation::DoublingDiagnosticBoundary => std::string::String::from("H"),
    }
}
