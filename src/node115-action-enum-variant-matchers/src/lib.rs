//! Exact name-to-tag mappings for three node #115 action enum visitors.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionVariantSet {
    Perp,
    Short114,
    Tag18,
}

pub const PERP_WIRE_NAMES: [&str; 17] = [
    "registerAsset",
    "setOracle",
    "insertMarginTable",
    "setFeeRecipient",
    "haltTrading",
    "setMarginTableIds",
    "setOpenInterestCaps",
    "setFundingMultipliers",
    "setMarginModes",
    "setDeployerFees",
    "setFeeScale",
    "setFundingInterestRates",
    "disableDex",
    "setPerpAnnotation",
    "migrateDexQuoteToken",
    "setFundingClamps",
    "hip3Star",
];

pub const SHORT114_WIRE_NAMES: [&str; 114] = [
    "a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
    "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
    "N", "O", "P", "Q", "R", "S", "T", "W", "X", "Y", "Z", "aa", "bb", "cc", "dd", "ee", "ff",
    "gg", "hh", "ii", "jj", "kk", "mm", "nn", "oo", "pp", "qq", "rr", "ss", "tt", "uu", "vv", "ww",
    "xx", "yy", "zz", "AA", "BB", "CC", "DD", "EE", "FF", "HH", "II", "JJ", "KK", "LL", "OO", "PP",
    "QQ", "RR", "TT", "UU", "VV", "WW", "XX", "YY", "ZZ", "aaa", "bbb", "ccc", "fff", "ggg", "hhh",
    "iii", "jjj", "kkk", "lll", "mmm", "nnn", "ooo", "ppp", "qqq", "rrr", "sss", "ttt",
];

pub const TAG18_WIRE_NAMES: [&str; 18] = [
    "e", "r", "b", "btp", "P", "Ps", "mu", "f", "t", "dp", "du", "pmv", "pma", "pmu", "rl", "mbs",
    "adl", "ri",
];

impl ActionVariantSet {
    /// Exact byte matching; aliases deliberately return the same variant tag.
    pub fn from_bytes(self, input: &[u8]) -> Option<u8> {
        match self {
            Self::Perp => match input {
                b"registerAsset" => Some(0),
                b"setOracle" => Some(1),
                b"insertMarginTable" => Some(2),
                b"setFeeRecipient" => Some(3),
                b"haltTrading" => Some(4),
                b"setMarginTableIds" => Some(5),
                b"setOpenInterestCaps" => Some(6),
                b"setFundingMultipliers" => Some(7),
                b"setMarginModes" => Some(8),
                b"setDeployerFees" => Some(9),
                b"setFeeScale" => Some(9),
                b"setFundingInterestRates" => Some(10),
                b"disableDex" => Some(11),
                b"setPerpAnnotation" => Some(12),
                b"migrateDexQuoteToken" => Some(13),
                b"setFundingClamps" => Some(14),
                b"hip3Star" => Some(15),
                _ => None,
            },
            Self::Short114 => match input {
                b"a" => Some(0),
                b"b" => Some(1),
                b"c" => Some(2),
                b"d" => Some(3),
                b"e" => Some(4),
                b"f" => Some(5),
                b"g" => Some(6),
                b"h" => Some(7),
                b"j" => Some(8),
                b"k" => Some(9),
                b"l" => Some(10),
                b"m" => Some(11),
                b"n" => Some(12),
                b"o" => Some(13),
                b"p" => Some(14),
                b"q" => Some(15),
                b"r" => Some(16),
                b"s" => Some(17),
                b"t" => Some(18),
                b"u" => Some(19),
                b"v" => Some(20),
                b"w" => Some(21),
                b"x" => Some(22),
                b"y" => Some(23),
                b"z" => Some(24),
                b"A" => Some(25),
                b"B" => Some(26),
                b"C" => Some(27),
                b"D" => Some(28),
                b"E" => Some(29),
                b"F" => Some(30),
                b"G" => Some(31),
                b"H" => Some(32),
                b"I" => Some(33),
                b"J" => Some(34),
                b"K" => Some(35),
                b"L" => Some(36),
                b"M" => Some(37),
                b"N" => Some(38),
                b"O" => Some(39),
                b"P" => Some(40),
                b"Q" => Some(41),
                b"R" => Some(42),
                b"S" => Some(43),
                b"T" => Some(44),
                b"W" => Some(45),
                b"X" => Some(46),
                b"Y" => Some(47),
                b"Z" => Some(48),
                b"aa" => Some(49),
                b"bb" => Some(50),
                b"cc" => Some(51),
                b"dd" => Some(52),
                b"ee" => Some(53),
                b"ff" => Some(54),
                b"gg" => Some(55),
                b"hh" => Some(56),
                b"ii" => Some(57),
                b"jj" => Some(58),
                b"kk" => Some(59),
                b"mm" => Some(60),
                b"nn" => Some(61),
                b"oo" => Some(62),
                b"pp" => Some(63),
                b"qq" => Some(64),
                b"rr" => Some(65),
                b"ss" => Some(66),
                b"tt" => Some(67),
                b"uu" => Some(68),
                b"vv" => Some(69),
                b"ww" => Some(70),
                b"xx" => Some(71),
                b"yy" => Some(72),
                b"zz" => Some(73),
                b"AA" => Some(74),
                b"BB" => Some(75),
                b"CC" => Some(76),
                b"DD" => Some(77),
                b"EE" => Some(78),
                b"FF" => Some(79),
                b"HH" => Some(80),
                b"II" => Some(81),
                b"JJ" => Some(82),
                b"KK" => Some(83),
                b"LL" => Some(84),
                b"OO" => Some(85),
                b"PP" => Some(86),
                b"QQ" => Some(87),
                b"RR" => Some(88),
                b"TT" => Some(89),
                b"UU" => Some(90),
                b"VV" => Some(91),
                b"WW" => Some(92),
                b"XX" => Some(93),
                b"YY" => Some(94),
                b"ZZ" => Some(95),
                b"aaa" => Some(96),
                b"bbb" => Some(97),
                b"ccc" => Some(98),
                b"fff" => Some(99),
                b"ggg" => Some(100),
                b"hhh" => Some(101),
                b"iii" => Some(102),
                b"jjj" => Some(103),
                b"kkk" => Some(104),
                b"lll" => Some(105),
                b"mmm" => Some(106),
                b"nnn" => Some(107),
                b"ooo" => Some(108),
                b"ppp" => Some(109),
                b"qqq" => Some(110),
                b"rrr" => Some(111),
                b"sss" => Some(112),
                b"ttt" => Some(113),
                _ => None,
            },
            Self::Tag18 => match input {
                b"e" => Some(0),
                b"r" => Some(1),
                b"b" => Some(2),
                b"btp" => Some(3),
                b"P" => Some(4),
                b"Ps" => Some(5),
                b"mu" => Some(6),
                b"f" => Some(7),
                b"t" => Some(8),
                b"dp" => Some(9),
                b"du" => Some(10),
                b"pmv" => Some(11),
                b"pma" => Some(12),
                b"pmu" => Some(13),
                b"rl" => Some(14),
                b"mbs" => Some(15),
                b"adl" => Some(16),
                b"ri" => Some(17),
                _ => None,
            },
        }
    }

    pub const fn visit_word(tag: u8) -> u16 {
        0x09 | ((tag as u16) << 8)
    }
}

#[cfg(test)]
mod tests {
    use super::{ActionVariantSet, PERP_WIRE_NAMES, SHORT114_WIRE_NAMES, TAG18_WIRE_NAMES};
    use std::collections::BTreeMap;

    const CASES: &str =
        include_str!("../../../research/work-items/RE-010-enum-variant-matchers-115/cases.tsv");
    const NAMES: &str =
        include_str!("../../../research/work-items/RE-010-enum-variant-matchers-115/names.tsv");

    fn columns(line: &str) -> Vec<&str> {
        line.split('\t').collect()
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => panic!("invalid hex in committed evidence"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    fn set(label: &str) -> ActionVariantSet {
        match label {
            "PERP" => ActionVariantSet::Perp,
            "SHORT114" => ActionVariantSet::Short114,
            "TAG18" => ActionVariantSet::Tag18,
            _ => panic!("unknown enum label in committed evidence"),
        }
    }

    #[test]
    fn exact_name_cases_match_the_committed_model() {
        let mut checked = 0;
        for line in CASES.lines().skip(1) {
            let c = columns(line);
            let got = set(c[0]).from_bytes(&decode_hex(c[2]));
            if let Some(expected) = c[4].strip_prefix("ok:") {
                assert_eq!(got, Some(expected.parse().unwrap()), "{} {}", c[0], c[2]);
            } else {
                assert!(c[4].starts_with("unknown:"));
                assert_eq!(got, None, "{} {}", c[0], c[2]);
            }
            assert_eq!(c[5], "=");
            if std::str::from_utf8(&decode_hex(c[2])).is_ok() {
                assert_eq!(c[6], "=");
            } else {
                assert_eq!(c[6], "not_str");
            }
            checked += 1;
        }
        assert_eq!(checked, 4_271);
    }

    #[test]
    fn pools_aliases_and_tagged_words_are_preserved() {
        let arrays = [
            ("PERP", PERP_WIRE_NAMES.as_slice()),
            ("SHORT114", SHORT114_WIRE_NAMES.as_slice()),
            ("TAG18", TAG18_WIRE_NAMES.as_slice()),
        ];
        let names: BTreeMap<_, _> = NAMES
            .lines()
            .skip(1)
            .map(|line| {
                let c = columns(line);
                (
                    (c[0], c[3]),
                    (
                        c[1].parse::<usize>().unwrap(),
                        c[2].parse::<u8>().unwrap(),
                        u16::from_str_radix(c[7].trim_start_matches("0x"), 16).unwrap(),
                    ),
                )
            })
            .collect();
        for (label, pool) in arrays {
            for (position, name) in pool.iter().enumerate() {
                let (expected_position, tag, word) = names[&(label, *name)];
                assert_eq!(expected_position, position);
                assert_eq!(set(label).from_bytes(name.as_bytes()), Some(tag));
                assert_eq!(ActionVariantSet::visit_word(tag), word);
            }
        }
    }
}
