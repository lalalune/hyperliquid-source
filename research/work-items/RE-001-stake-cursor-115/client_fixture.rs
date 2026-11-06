fn evaluate_row(words: &[u64]) -> Result<String, &'static str> {
    if words.len() != 6 || words[0] > 1 || words[5] > 65535 {
        return Err("qualified six-word record required");
    }
    let (index, word, aux, mode, tag) = (words[1], words[2], words[3], words[4], words[5] as u16);
    if words[0] == 0 {
        if aux > 255 || mode > 255 {
            return Err("input byte required");
        }
        let payload = std::array::from_fn(|i| 37_u8.wrapping_add((i as u8).wrapping_mul(19)));
        let out = cursor_prefix(index, word, aux as u8, mode as u8, payload);
        let next = match out.next {
            CursorNext::DiagnosticBoundary => "D".to_string(),
            CursorNext::Terminal { index } => format!("T:{index}"),
            CursorNext::NumericHelperBoundary {
                index,
                bonus,
                selector,
                payload,
            } => {
                let raw: String = payload.iter().map(|b| format!("{b:02x}")).collect();
                format!("H:{index}:{}:{selector}:{raw}", u8::from(bonus))
            }
        };
        Ok(format!(
            "E:{}:{}:{tag}:{next}",
            out.cursor,
            u8::from(out.wrote_cursor)
        ))
    } else {
        if index > 3 || mode > 3 || aux > 1 {
            return Err("outside measured post-helper domain");
        }
        let out = post_helper(
            Index4::new(index as u8).unwrap(),
            word,
            aux == 1,
            ObservedColumn::new(mode as u8).unwrap(),
            tag,
        );
        let next = match out.next {
            ItemNext::Yield(product) => format!("Y:{product}"),
            ItemNext::FailedRawC5 => "F".to_string(),
            ItemNext::ExistingCleanupBoundary => "X".to_string(),
        };
        Ok(format!(
            "P:{}:{}:{next}",
            out.output_tag,
            u8::from(out.wrote_tag)
        ))
    }
}
