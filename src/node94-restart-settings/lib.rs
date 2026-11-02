//! Normal-return projection over a supplied final path component and helper words.
//! File lookup, parsers, global state, diagnostics and original ABI are unclosed.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Json,
    Rmp,
}

pub fn codec(component: &[u8]) -> Codec {
    if let Some(dot) = component.iter().rposition(|&b| b == b'.') {
        if dot > 0
            && component.len() - dot == 4
            && component[dot + 1..].eq_ignore_ascii_case(b"rmp")
        {
            return Codec::Rmp;
        }
    }
    Codec::Json
}

/// Specialize only the measured normal helper-return protocol.
pub fn loader_value(
    codec: Codec,
    eligible: bool,
    read_word: u64,
    parse_tag: u64,
    payload: u64,
) -> u64 {
    if !eligible || read_word == (1 << 63) {
        return 0;
    }
    let success = match codec {
        Codec::Rmp => parse_tag as u8 == 9,
        Codec::Json => parse_tag & 1 == 0,
    };
    if success {
        payload
    } else {
        0
    }
}

pub fn page_count(word: u64) -> u64 {
    word + u64::from(word == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn component_is_not_a_full_path_parser() {
        assert_eq!(codec(b".rmp"), Codec::Json);
        assert_eq!(codec(b"state.RmP"), Codec::Rmp);
        assert_eq!(codec(b"state.rmpx"), Codec::Json);
    }
    #[test]
    fn parser_tags_are_different_protocols() {
        assert_eq!(loader_value(Codec::Rmp, true, 0, 0x109, 7), 7);
        assert_eq!(loader_value(Codec::Json, true, 0, 2, 7), 7);
        assert_eq!(loader_value(Codec::Json, true, 1 << 63, 0, 7), 0);
        assert_eq!(page_count(u64::MAX), u64::MAX);
        assert_eq!(page_count(0), 1);
    }
}
