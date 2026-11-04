// Input/output adapter only. No original expectations or alternate arithmetic.
fn observation_text(value: Observation) -> std::string::String {
    match value {
        Observation::MarkOrProductBoundary => std::string::String::from("M"),
        Observation::EntrySignBoundary => std::string::String::from("E"),
        Observation::SubtractionBoundary => std::string::String::from("S"),
        Observation::Normal { product_word, pnl_word, division: None } =>
            std::format!("V:{product_word}:{pnl_word}:N"),
        Observation::Normal { product_word, pnl_word, division: Some(d) } => {
            let width = match d.width { Width::Narrow32 => 32, Width::Wide64 => 64 };
            std::format!("V:{product_word}:{pnl_word}:{width}:{}:{}", d.quotient, d.remainder)
        }
    }
}
