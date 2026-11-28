#![forbid(unsafe_code)]
#![allow(dead_code)]
use serde::Deserialize;
use tikv_jemallocator::Jemalloc;
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;
#[derive(Deserialize, Debug)]
enum CompactEnum0 {
    #[serde(rename = "B", alias = "Bid")] V0,
    #[serde(rename = "A", alias = "Ask")] V1,
}
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum0 { A { x: CompactEnum0 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum0 { A(CompactEnum0), B(u64) }
#[derive(Deserialize, Debug)]
enum CompactEnum1 { #[serde(rename = "a")] V0, #[serde(rename = "b")] V1, #[serde(rename = "c")] V2, #[serde(rename = "d")] V3, #[serde(rename = "e")] V4, #[serde(rename = "f")] V5, #[serde(rename = "g")] V6, #[serde(rename = "h")] V7, #[serde(rename = "j")] V8, #[serde(rename = "k")] V9, #[serde(rename = "l")] V10, #[serde(rename = "m")] V11, #[serde(rename = "n")] V12, #[serde(rename = "o")] V13, #[serde(rename = "p")] V14, #[serde(rename = "q")] V15, #[serde(rename = "r")] V16, #[serde(rename = "s")] V17, #[serde(rename = "t")] V18, #[serde(rename = "u")] V19, #[serde(rename = "v")] V20, #[serde(rename = "w")] V21, #[serde(rename = "x")] V22, #[serde(rename = "y")] V23, #[serde(rename = "z")] V24, #[serde(rename = "A")] V25, #[serde(rename = "B")] V26, #[serde(rename = "C")] V27, #[serde(rename = "D")] V28, #[serde(rename = "E")] V29, #[serde(rename = "F")] V30, #[serde(rename = "G")] V31, #[serde(rename = "H")] V32, #[serde(rename = "I")] V33, #[serde(rename = "J")] V34, #[serde(rename = "K")] V35, #[serde(rename = "L")] V36, #[serde(rename = "M")] V37, #[serde(rename = "N")] V38, #[serde(rename = "O")] V39, #[serde(rename = "P")] V40, #[serde(rename = "Q")] V41, #[serde(rename = "R")] V42, #[serde(rename = "S")] V43, #[serde(rename = "T")] V44, #[serde(rename = "W")] V45, #[serde(rename = "X")] V46, #[serde(rename = "Y")] V47, #[serde(rename = "Z")] V48, #[serde(rename = "aa")] V49, #[serde(rename = "bb")] V50, #[serde(rename = "cc")] V51, #[serde(rename = "dd")] V52, #[serde(rename = "ee")] V53, #[serde(rename = "ff")] V54, #[serde(rename = "gg")] V55, #[serde(rename = "hh")] V56, #[serde(rename = "ii")] V57, #[serde(rename = "jj")] V58, #[serde(rename = "kk")] V59, #[serde(rename = "mm")] V60, #[serde(rename = "nn")] V61, #[serde(rename = "oo")] V62, #[serde(rename = "pp")] V63, #[serde(rename = "qq")] V64, #[serde(rename = "rr")] V65, #[serde(rename = "ss")] V66, #[serde(rename = "tt")] V67, #[serde(rename = "uu")] V68, #[serde(rename = "vv")] V69, #[serde(rename = "ww")] V70, #[serde(rename = "xx")] V71, #[serde(rename = "yy")] V72, #[serde(rename = "zz")] V73, #[serde(rename = "AA")] V74, #[serde(rename = "BB")] V75, #[serde(rename = "CC")] V76, #[serde(rename = "DD")] V77, #[serde(rename = "EE")] V78, #[serde(rename = "FF")] V79, #[serde(rename = "HH")] V80, #[serde(rename = "II")] V81, #[serde(rename = "JJ")] V82, #[serde(rename = "KK")] V83, #[serde(rename = "LL")] V84, #[serde(rename = "OO")] V85, #[serde(rename = "PP")] V86, #[serde(rename = "QQ")] V87, #[serde(rename = "RR")] V88, #[serde(rename = "TT")] V89, #[serde(rename = "UU")] V90, #[serde(rename = "VV")] V91, #[serde(rename = "WW")] V92, #[serde(rename = "XX")] V93, #[serde(rename = "YY")] V94, #[serde(rename = "ZZ")] V95, #[serde(rename = "aaa")] V96, #[serde(rename = "bbb")] V97, #[serde(rename = "ccc")] V98, #[serde(rename = "fff")] V99, #[serde(rename = "ggg")] V100, #[serde(rename = "hhh")] V101, #[serde(rename = "iii")] V102, #[serde(rename = "jjj")] V103, #[serde(rename = "kkk")] V104, #[serde(rename = "lll")] V105, #[serde(rename = "mmm")] V106, #[serde(rename = "nnn")] V107, #[serde(rename = "ooo")] V108, #[serde(rename = "ppp")] V109, #[serde(rename = "qqq")] V110, #[serde(rename = "rrr")] V111, #[serde(rename = "sss")] V112, #[serde(rename = "ttt")] V113 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum1 { A { x: CompactEnum1 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum1 { A(CompactEnum1), B(u64) }
#[derive(Deserialize, Debug)]
enum CompactEnum2 { #[serde(rename = "e")] V0, #[serde(rename = "r")] V1, #[serde(rename = "b")] V2, #[serde(rename = "btp")] V3, #[serde(rename = "P")] V4, #[serde(rename = "Ps")] V5, #[serde(rename = "mu")] V6, #[serde(rename = "f")] V7, #[serde(rename = "t")] V8, #[serde(rename = "dp")] V9, #[serde(rename = "du")] V10, #[serde(rename = "pmv")] V11, #[serde(rename = "pma")] V12, #[serde(rename = "pmu")] V13, #[serde(rename = "rl")] V14, #[serde(rename = "mbs")] V15, #[serde(rename = "adl")] V16, #[serde(rename = "ri")] V17 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum2 { A { x: CompactEnum2 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum2 { A(CompactEnum2), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct2 { #[serde(rename = "e")] f0: u8, #[serde(rename = "r")] f1: u8, #[serde(rename = "b")] f2: u8, #[serde(rename = "btp")] f3: u8, #[serde(rename = "P")] f4: u8, #[serde(rename = "Ps")] f5: u8, #[serde(rename = "mu")] f6: u8, #[serde(rename = "f")] f7: u8, #[serde(rename = "t")] f8: u8, #[serde(rename = "dp")] f9: u8, #[serde(rename = "du")] f10: u8, #[serde(rename = "pmv")] f11: u8, #[serde(rename = "pma")] f12: u8, #[serde(rename = "pmu")] f13: u8, #[serde(rename = "rl")] f14: u8, #[serde(rename = "mbs")] f15: u8, #[serde(rename = "adl")] f16: u8, #[serde(rename = "ri")] f17: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct2 { #[serde(rename = "v")] V(CompactStruct2) }
#[derive(Deserialize, Debug)]
enum CompactEnum3 { #[serde(rename = "t")] V0, #[serde(rename = "l")] V1, #[serde(rename = "y")] V2, #[serde(rename = "b")] V3, #[serde(rename = "s")] V4, #[serde(rename = "ub")] V5, #[serde(rename = "us")] V6, #[serde(rename = "Mp")] V7, #[serde(rename = "mp")] V8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum3 { A { x: CompactEnum3 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum3 { A(CompactEnum3), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct3 { #[serde(rename = "t")] f0: u8, #[serde(rename = "l")] f1: u8, #[serde(rename = "y")] f2: u8, #[serde(rename = "b")] f3: u8, #[serde(rename = "s")] f4: u8, #[serde(rename = "ub")] f5: u8, #[serde(rename = "us")] f6: u8, #[serde(rename = "Mp")] f7: u8, #[serde(rename = "mp")] f8: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct3 { #[serde(rename = "v")] V(CompactStruct3) }
#[derive(Deserialize, Debug)]
enum CompactEnum4 { #[serde(rename = "D")] V0, #[serde(rename = "Q")] V1, #[serde(rename = "C")] V2, #[serde(rename = "P")] V3, #[serde(rename = "G")] V4, #[serde(rename = "O")] V5, #[serde(rename = "E")] V6 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum4 { A { x: CompactEnum4 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum4 { A(CompactEnum4), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct4 { #[serde(rename = "D")] f0: u8, #[serde(rename = "Q")] f1: u8, #[serde(rename = "C")] f2: u8, #[serde(rename = "P")] f3: u8, #[serde(rename = "G")] f4: u8, #[serde(rename = "O")] f5: u8, #[serde(rename = "E")] f6: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct4 { #[serde(rename = "v")] V(CompactStruct4) }
#[derive(Deserialize, Debug)]
enum CompactEnum5 { #[serde(rename = "l")] V0, #[serde(rename = "L")] V1, #[serde(rename = "i")] V2, #[serde(rename = "d")] V3, #[serde(rename = "b")] V4, #[serde(rename = "o")] V5 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum5 { A { x: CompactEnum5 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum5 { A(CompactEnum5), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct5 { #[serde(rename = "l")] f0: u8, #[serde(rename = "L")] f1: u8, #[serde(rename = "i")] f2: u8, #[serde(rename = "d")] f3: u8, #[serde(rename = "b")] f4: u8, #[serde(rename = "o")] f5: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct5 { #[serde(rename = "v")] V(CompactStruct5) }
#[derive(Deserialize, Debug)]
enum CompactEnum6 { #[serde(rename = "v")] V0, #[serde(rename = "n")] V1, #[serde(rename = "d")] V2, #[serde(rename = "c")] V3, #[serde(rename = "l")] V4, #[serde(rename = "a")] V5, #[serde(rename = "w")] V6, #[serde(rename = "p")] V7, #[serde(rename = "s")] V8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum6 { A { x: CompactEnum6 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum6 { A(CompactEnum6), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct6 { #[serde(rename = "v")] f0: u8, #[serde(rename = "n")] f1: u8, #[serde(rename = "d")] f2: u8, #[serde(rename = "c")] f3: u8, #[serde(rename = "l")] f4: u8, #[serde(rename = "a")] f5: u8, #[serde(rename = "w")] f6: u8, #[serde(rename = "p")] f7: u8, #[serde(rename = "s")] f8: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct6 { #[serde(rename = "v")] V(CompactStruct6) }
#[derive(Deserialize, Debug)]
enum CompactEnum7 { #[serde(rename = "d")] V0, #[serde(rename = "D")] V1, #[serde(rename = "r")] V2, #[serde(rename = "w")] V3, #[serde(rename = "e")] V4, #[serde(rename = "b")] V5, #[serde(rename = "m")] V6, #[serde(rename = "a")] V7, #[serde(rename = "A")] V8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum7 { A { x: CompactEnum7 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum7 { A(CompactEnum7), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct7 { #[serde(rename = "d")] f0: u8, #[serde(rename = "D")] f1: u8, #[serde(rename = "r")] f2: u8, #[serde(rename = "w")] f3: u8, #[serde(rename = "e")] f4: u8, #[serde(rename = "b")] f5: u8, #[serde(rename = "m")] f6: u8, #[serde(rename = "a")] f7: u8, #[serde(rename = "A")] f8: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct7 { #[serde(rename = "v")] V(CompactStruct7) }
#[derive(Deserialize, Debug)]
enum CompactEnum8 { #[serde(rename = "m")] V0, #[serde(rename = "n")] V1, #[serde(rename = "r")] V2, #[serde(rename = "k")] V3, #[serde(rename = "c")] V4 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum8 { A { x: CompactEnum8 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum8 { A(CompactEnum8), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct8 { #[serde(rename = "m")] f0: u8, #[serde(rename = "n")] f1: u8, #[serde(rename = "r")] f2: u8, #[serde(rename = "k")] f3: u8, #[serde(rename = "c")] f4: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct8 { #[serde(rename = "v")] V(CompactStruct8) }
#[derive(Deserialize, Debug)]
enum CompactEnum9 { #[serde(rename = "e")] V0, #[serde(rename = "n")] V1, #[serde(rename = "t")] V2, #[serde(rename = "m")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum9 { A { x: CompactEnum9 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum9 { A(CompactEnum9), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct9 { #[serde(rename = "e")] f0: u8, #[serde(rename = "n")] f1: u8, #[serde(rename = "t")] f2: u8, #[serde(rename = "m")] f3: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct9 { #[serde(rename = "v")] V(CompactStruct9) }
#[derive(Deserialize, Debug)]
enum CompactEnum10 { #[serde(rename = "d")] V0, #[serde(rename = "s")] V1, #[serde(rename = "i")] V2, #[serde(rename = "m")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum10 { A { x: CompactEnum10 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum10 { A(CompactEnum10), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct10 { #[serde(rename = "d")] f0: u8, #[serde(rename = "s")] f1: u8, #[serde(rename = "i")] f2: u8, #[serde(rename = "m")] f3: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct10 { #[serde(rename = "v")] V(CompactStruct10) }
#[derive(Deserialize, Debug)]
enum CompactEnum11 { #[serde(rename = "d")] V0, #[serde(rename = "v")] V1, #[serde(rename = "l")] V2, #[serde(rename = "a")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum11 { A { x: CompactEnum11 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum11 { A(CompactEnum11), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct11 { #[serde(rename = "d")] f0: u8, #[serde(rename = "v")] f1: u8, #[serde(rename = "l")] f2: u8, #[serde(rename = "a")] f3: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct11 { #[serde(rename = "v")] V(CompactStruct11) }
#[derive(Deserialize, Debug)]
enum CompactEnum12 { #[serde(rename = "t")] V0, #[serde(rename = "p")] V1, #[serde(rename = "P")] V2, #[serde(rename = "c")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum12 { A { x: CompactEnum12 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum12 { A(CompactEnum12), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct12 { #[serde(rename = "t")] f0: u8, #[serde(rename = "p")] f1: u8, #[serde(rename = "P")] f2: u8, #[serde(rename = "c")] f3: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct12 { #[serde(rename = "v")] V(CompactStruct12) }
#[derive(Deserialize, Debug)]
enum CompactEnum13 { #[serde(rename = "e")] V0, #[serde(rename = "a")] V1, #[serde(rename = "d")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum13 { A { x: CompactEnum13 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum13 { A(CompactEnum13), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct13 { #[serde(rename = "e")] f0: u8, #[serde(rename = "a")] f1: u8, #[serde(rename = "d")] f2: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct13 { #[serde(rename = "v")] V(CompactStruct13) }
#[derive(Deserialize, Debug)]
enum CompactEnum14 { #[serde(rename = "e")] V0, #[serde(rename = "x")] V1, #[serde(rename = "d")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum14 { A { x: CompactEnum14 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum14 { A(CompactEnum14), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct14 { #[serde(rename = "e")] f0: u8, #[serde(rename = "x")] f1: u8, #[serde(rename = "d")] f2: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct14 { #[serde(rename = "v")] V(CompactStruct14) }
#[derive(Deserialize, Debug)]
enum CompactEnum15 { #[serde(rename = "H")] V0, #[serde(rename = "R")] V1, #[serde(rename = "S")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum15 { A { x: CompactEnum15 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum15 { A(CompactEnum15), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct15 { #[serde(rename = "H")] f0: u8, #[serde(rename = "R")] f1: u8, #[serde(rename = "S")] f2: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct15 { #[serde(rename = "v")] V(CompactStruct15) }
#[derive(Deserialize, Debug)]
enum CompactEnum16 { #[serde(rename = "b")] V0, #[serde(rename = "f")] V1, #[serde(rename = "s")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum16 { A { x: CompactEnum16 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum16 { A(CompactEnum16), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct16 { #[serde(rename = "b")] f0: u8, #[serde(rename = "f")] f1: u8, #[serde(rename = "s")] f2: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct16 { #[serde(rename = "v")] V(CompactStruct16) }
#[derive(Deserialize, Debug)]
enum CompactEnum17 { #[serde(rename = "Pct")] V0, #[serde(rename = "Px")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum17 { A { x: CompactEnum17 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum17 { A(CompactEnum17), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct17 { #[serde(rename = "Pct")] f0: u8, #[serde(rename = "Px")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct17 { #[serde(rename = "v")] V(CompactStruct17) }
#[derive(Deserialize, Debug)]
enum CompactEnum18 { #[serde(rename = "pct")] V0, #[serde(rename = "px")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum18 { A { x: CompactEnum18 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum18 { A(CompactEnum18), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct18 { #[serde(rename = "pct")] f0: u8, #[serde(rename = "px")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct18 { #[serde(rename = "v")] V(CompactStruct18) }
#[derive(Deserialize, Debug)]
enum CompactEnum19 { #[serde(rename = "tp")] V0, #[serde(rename = "sl")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum19 { A { x: CompactEnum19 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum19 { A(CompactEnum19), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct19 { #[serde(rename = "tp")] f0: u8, #[serde(rename = "sl")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct19 { #[serde(rename = "v")] V(CompactStruct19) }
#[derive(Deserialize, Debug)]
enum CompactEnum20 { #[serde(rename = "vip")] V0, #[serde(rename = "mm")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum20 { A { x: CompactEnum20 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum20 { A(CompactEnum20), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct20 { #[serde(rename = "vip")] f0: u8, #[serde(rename = "mm")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct20 { #[serde(rename = "v")] V(CompactStruct20) }
#[derive(Deserialize, Debug)]
enum CompactEnum21 { #[serde(rename = "D")] V0, #[serde(rename = "E")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum21 { A { x: CompactEnum21 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum21 { A(CompactEnum21), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct21 { #[serde(rename = "D")] f0: u8, #[serde(rename = "E")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct21 { #[serde(rename = "v")] V(CompactStruct21) }
#[derive(Deserialize, Debug)]
enum CompactEnum22 { #[serde(rename = "D")] V0, #[serde(rename = "U")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum22 { A { x: CompactEnum22 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum22 { A(CompactEnum22), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct22 { #[serde(rename = "D")] f0: u8, #[serde(rename = "U")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct22 { #[serde(rename = "v")] V(CompactStruct22) }
#[derive(Deserialize, Debug)]
enum CompactEnum23 { #[serde(rename = "G")] V0, #[serde(rename = "P")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum23 { A { x: CompactEnum23 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum23 { A(CompactEnum23), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct23 { #[serde(rename = "G")] f0: u8, #[serde(rename = "P")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct23 { #[serde(rename = "v")] V(CompactStruct23) }
#[derive(Deserialize, Debug)]
enum CompactEnum24 { #[serde(rename = "v")] V0, #[serde(rename = "o")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum24 { A { x: CompactEnum24 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum24 { A(CompactEnum24), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct24 { #[serde(rename = "v")] f0: u8, #[serde(rename = "o")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct24 { #[serde(rename = "v")] V(CompactStruct24) }
#[derive(Deserialize, Debug)]
enum CompactEnum25 { #[serde(rename = "b")] V0, #[serde(rename = "c")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum25 { A { x: CompactEnum25 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum25 { A(CompactEnum25), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct25 { #[serde(rename = "b")] f0: u8, #[serde(rename = "c")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct25 { #[serde(rename = "v")] V(CompactStruct25) }
#[derive(Deserialize, Debug)]
enum CompactEnum26 { #[serde(rename = "b")] V0, #[serde(rename = "s")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum26 { A { x: CompactEnum26 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum26 { A(CompactEnum26), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct26 { #[serde(rename = "b")] f0: u8, #[serde(rename = "s")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct26 { #[serde(rename = "v")] V(CompactStruct26) }
#[derive(Deserialize, Debug)]
enum CompactEnum27 { #[serde(rename = "s")] V0, #[serde(rename = "v")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum27 { A { x: CompactEnum27 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum27 { A(CompactEnum27), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct27 { #[serde(rename = "s")] f0: u8, #[serde(rename = "v")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct27 { #[serde(rename = "v")] V(CompactStruct27) }
#[derive(Deserialize, Debug)]
enum CompactEnum28 { #[serde(rename = "n")] V0, #[serde(rename = "m")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum28 { A { x: CompactEnum28 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum28 { A(CompactEnum28), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct28 { #[serde(rename = "n")] f0: u8, #[serde(rename = "m")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct28 { #[serde(rename = "v")] V(CompactStruct28) }
#[derive(Deserialize, Debug)]
enum CompactEnum29 { #[serde(rename = "s")] V0, #[serde(rename = "t")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum29 { A { x: CompactEnum29 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum29 { A(CompactEnum29), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct29 { #[serde(rename = "s")] f0: u8, #[serde(rename = "t")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct29 { #[serde(rename = "v")] V(CompactStruct29) }
#[derive(Deserialize, Debug)]
enum CompactEnum30 { #[serde(rename = "s")] V0, #[serde(rename = "p")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum30 { A { x: CompactEnum30 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum30 { A(CompactEnum30), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct30 { #[serde(rename = "s")] f0: u8, #[serde(rename = "p")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct30 { #[serde(rename = "v")] V(CompactStruct30) }
#[derive(Deserialize, Debug)]
enum CompactEnum31 { #[serde(rename = "n")] V0, #[serde(rename = "p")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum31 { A { x: CompactEnum31 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum31 { A(CompactEnum31), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct31 { #[serde(rename = "n")] f0: u8, #[serde(rename = "p")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct31 { #[serde(rename = "v")] V(CompactStruct31) }
#[derive(Deserialize, Debug)]
enum CompactEnum32 { #[serde(rename = "i")] V0, #[serde(rename = "a")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum32 { A { x: CompactEnum32 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum32 { A(CompactEnum32), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct32 { #[serde(rename = "i")] f0: u8, #[serde(rename = "a")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct32 { #[serde(rename = "v")] V(CompactStruct32) }
#[derive(Deserialize, Debug)]
enum CompactEnum33 { #[serde(rename = "u")] V0, #[serde(rename = "a")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum33 { A { x: CompactEnum33 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum33 { A(CompactEnum33), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct33 { #[serde(rename = "u")] f0: u8, #[serde(rename = "a")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct33 { #[serde(rename = "v")] V(CompactStruct33) }
#[derive(Deserialize, Debug)]
enum CompactEnum34 { #[serde(rename = "t")] V0, #[serde(rename = "w")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum34 { A { x: CompactEnum34 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum34 { A(CompactEnum34), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct34 { #[serde(rename = "t")] f0: u8, #[serde(rename = "w")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct34 { #[serde(rename = "v")] V(CompactStruct34) }
#[derive(Deserialize, Debug)]
enum CompactEnum35 { #[serde(rename = "t")] V0, #[serde(rename = "s")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactEnum35 { A { x: CompactEnum35 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagCompactEnum35 { A(CompactEnum35), B(u64) }
#[derive(Deserialize, Debug)] #[serde(deny_unknown_fields)]
struct CompactStruct35 { #[serde(rename = "t")] f0: u8, #[serde(rename = "s")] f1: u8 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagCompactStruct35 { #[serde(rename = "v")] V(CompactStruct35) }
#[derive(Deserialize, Debug)]
enum W3Enum0 { #[serde(rename = "Alo")] V0, #[serde(rename = "Ioc")] V1, #[serde(rename = "Gtc")] V2, #[serde(rename = "FrontendMarket")] V3, #[serde(rename = "LiquidationMarket")] V4 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum0 { A { x: W3Enum0 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum0 { A(W3Enum0), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum1 { #[serde(rename = "Cross")] V0, #[serde(rename = "Isolated")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum1 { A { x: W3Enum1 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum1 { A(W3Enum1), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum2 { #[serde(rename = "Deposit")] V0, #[serde(rename = "InvalidatedWithdrawal")] V1, #[serde(rename = "RequestedWithdrawal")] V2, #[serde(rename = "FinalizedWithdrawal")] V3, #[serde(rename = "FinalizedValidatorSetUpdate")] V4, #[serde(rename = "RequestedValidatorSetUpdateEvent")] V5 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum2 { A { x: W3Enum2 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum2 { A(W3Enum2), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum3 { #[serde(rename = "Evm")] V0, #[serde(rename = "Broadcaster")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum3 { A { x: W3Enum3 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum3 { A(W3Enum3), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum4 { #[serde(rename = "Local")] V0, #[serde(rename = "Sandbox")] V1, #[serde(rename = "Testnet")] V2, #[serde(rename = "Mainnet")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum4 { A { x: W3Enum4 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum4 { A(W3Enum4), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum5 { #[serde(rename = "Main")] V0, #[serde(rename = "Hip3")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum5 { A { x: W3Enum5 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum5 { A(W3Enum5), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum6 { #[serde(rename = "Na")] V0, #[serde(rename = "UserDisabled")] V1, #[serde(rename = "ValidatorDisabled")] V2, #[serde(rename = "m")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum6 { A { x: W3Enum6 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum6 { A(W3Enum6), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum7 { #[serde(rename = "NoEvmDb")] V0 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum7 { A { x: W3Enum7 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum7 { A(W3Enum7), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum8 { #[serde(rename = "Oracle")] V0, #[serde(rename = "ReferenceOracle")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum8 { A { x: W3Enum8 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum8 { A(W3Enum8), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum9 { #[serde(rename = "Perp")] V0, #[serde(rename = "Spot")] V1, #[serde(rename = "Token")] V2, #[serde(rename = "Pdi")] V3, #[serde(rename = "ActivateDexAbstraction")] V4, #[serde(rename = "ActivateUnifiedAccount")] V5, #[serde(rename = "AllBoleTokens")] V6 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum9 { A { x: W3Enum9 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum9 { A(W3Enum9), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum10 { #[serde(rename = "Q")] V0, #[serde(rename = "N")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum10 { A { x: W3Enum10 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum10 { A(W3Enum10), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum11 { #[serde(rename = "Requested")] V0, #[serde(rename = "TradingUser")] V1, #[serde(rename = "StakingUser")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum11 { A { x: W3Enum11 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum11 { A(W3Enum11), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum12 { #[serde(rename = "Reth115")] V0 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum12 { A { x: W3Enum12 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum12 { A(W3Enum12), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum13 { #[serde(rename = "Spot")] V0, #[serde(rename = "Mark")] V1, #[serde(rename = "ExternalPerp")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum13 { A { x: W3Enum13 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum13 { A(W3Enum13), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum14 { #[serde(rename = "StandaloneOutcome")] V0, #[serde(rename = "Question")] V1, #[serde(rename = "QuestionOutcome")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum14 { A { x: W3Enum14 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum14 { A(W3Enum14), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum15 { #[serde(rename = "accelerated")] V0, #[serde(rename = "constitutional")] V1, #[serde(rename = "ecosystem")] V2, #[serde(rename = "electoral")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum15 { A { x: W3Enum15 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum15 { A(W3Enum15), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum16 { #[serde(rename = "borrow")] V0, #[serde(rename = "supply")] V1, #[serde(rename = "repay")] V2, #[serde(rename = "withdraw")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum16 { A { x: W3Enum16 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum16 { A(W3Enum16), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum17 { #[serde(rename = "create")] V0, #[serde(rename = "firstStorageSlot")] V1, #[serde(rename = "customStorageSlot")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum17 { A { x: W3Enum17 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum17 { A(W3Enum17), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum18 { #[serde(rename = "dateTime")] V0, #[serde(rename = "date")] V1, #[serde(rename = "string")] V2, #[serde(rename = "shortString")] V3, #[serde(rename = "hlPerp")] V4, #[serde(rename = "uInt")] V5, #[serde(rename = "uDecimal")] V6 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum18 { A { x: W3Enum18 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum18 { A(W3Enum18), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum19 { #[serde(rename = "disabled")] V0, #[serde(rename = "reduceOnly")] V1, #[serde(rename = "enabled")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum19 { A { x: W3Enum19 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum19 { A(W3Enum19), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum20 { #[serde(rename = "enabled")] V0, #[serde(rename = "disabled")] V1, #[serde(rename = "blocked")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum20 { A { x: W3Enum20 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum20 { A(W3Enum20), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum21 { #[serde(rename = "limit")] V0, #[serde(rename = "trigger")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum21 { A { x: W3Enum21 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum21 { A(W3Enum21), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum22 { #[serde(rename = "modifyApproval")] V0, #[serde(rename = "modifyBackstopLiquidatorApproval")] V1, #[serde(rename = "setReduceOnly")] V2, #[serde(rename = "cancel")] V3, #[serde(rename = "cancelAll")] V4, #[serde(rename = "order")] V5, #[serde(rename = "sendAsset")] V6 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum22 { A { x: W3Enum22 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum22 { A(W3Enum22), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum23 { #[serde(rename = "modifyApproval")] V0, #[serde(rename = "modifyBackstopLiquidatorApproval")] V1, #[serde(rename = "setReduceOnly")] V2, #[serde(rename = "cancel")] V3, #[serde(rename = "cancelAll")] V4, #[serde(rename = "order")] V5, #[serde(rename = "sendAsset")] V6, #[serde(rename = "setOracle")] V7 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum23 { A { x: W3Enum23 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum23 { A(W3Enum23), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum24 { #[serde(rename = "na")] V0, #[serde(rename = "normalTpsl")] V1, #[serde(rename = "positionTpsl")] V2, #[serde(rename = "p")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum24 { A { x: W3Enum24 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum24 { A(W3Enum24), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum25 { #[serde(rename = "noop")] V0, #[serde(rename = "approveAgent")] V1, #[serde(rename = "batchModify")] V2, #[serde(rename = "cancel")] V3, #[serde(rename = "cancelByCloid")] V4, #[serde(rename = "claimRewards")] V5, #[serde(rename = "createSubAccount")] V6, #[serde(rename = "createVault")] V7, #[serde(rename = "evmRawTx")] V8, #[serde(rename = "ForceIncreaseEpochAction")] V9, #[serde(rename = "liquidate")] V10, #[serde(rename = "linkStakingUser")] V11, #[serde(rename = "modify")] V12, #[serde(rename = "NetChildVaultPositionsAction")] V13, #[serde(rename = "order")] V14, #[serde(rename = "registerReferrer")] V15, #[serde(rename = "RegisterValidatorAction")] V16, #[serde(rename = "CValidatorAction")] V17, #[serde(rename = "scheduleCancel")] V18, #[serde(rename = "setDisplayName")] V19, #[serde(rename = "VoteGlobalAction")] V20, #[serde(rename = "validatorL1Vote")] V21, #[serde(rename = "validatorL1Stream")] V22, #[serde(rename = "validatorL1Status")] V23, #[serde(rename = "validatorL1UpdateReferenceOracle")] V24, #[serde(rename = "SetGlobalAction")] V25, #[serde(rename = "setReferrer")] V26, #[serde(rename = "spotDeploy")] V27, #[serde(rename = "spotUser")] V28, #[serde(rename = "spotSend")] V29, #[serde(rename = "SignValidatorSetUpdateAction")] V30, #[serde(rename = "subAccountModify")] V31, #[serde(rename = "subAccountTransfer")] V32, #[serde(rename = "subAccountSpotTransfer")] V33, #[serde(rename = "tokenDelegate")] V34, #[serde(rename = "twapCancel")] V35, #[serde(rename = "twapOrder")] V36, #[serde(rename = "updateIsolatedMargin")] V37, #[serde(rename = "topUpIsolatedOnlyMargin")] V38, #[serde(rename = "updateLeverage")] V39, #[serde(rename = "usdSend")] V40, #[serde(rename = "ValidatorSignWithdrawalAction")] V41, #[serde(rename = "vaultDistribute")] V42, #[serde(rename = "vaultModify")] V43, #[serde(rename = "vaultTransfer")] V44, #[serde(rename = "VoteEthDepositAction")] V45, #[serde(rename = "VoteEthFinalizedValidatorSetUpdateAction")] V46, #[serde(rename = "VoteEthFinalizedWithdrawalAction")] V47, #[serde(rename = "withdraw3")] V48, #[serde(rename = "govPropose")] V49, #[serde(rename = "govVote")] V50, #[serde(rename = "usdClassTransfer")] V51, #[serde(rename = "multiSig")] V52, #[serde(rename = "convertToMultiSigUser")] V53, #[serde(rename = "approveBuilderFee")] V54, #[serde(rename = "startFeeTrial")] V55, #[serde(rename = "SystemBoleAction")] V56, #[serde(rename = "SystemSpotSendAction")] V57, #[serde(rename = "deployerSendToEvmForFrozenUser")] V58, #[serde(rename = "SystemUsdClassTransferAction")] V59, #[serde(rename = "CSignerAction")] V60, #[serde(rename = "cWithdraw")] V61, #[serde(rename = "cDeposit")] V62, #[serde(rename = "cUserModify")] V63, #[serde(rename = "reassessFees")] V64, #[serde(rename = "evmUserModify")] V65, #[serde(rename = "reserveRequestWeight")] V66, #[serde(rename = "finalizeEvmContract")] V67, #[serde(rename = "perpDeploy")] V68, #[serde(rename = "sendAsset")] V69, #[serde(rename = "SystemApproveBuilderFeeAction")] V70, #[serde(rename = "SystemSendAssetAction")] V71, #[serde(rename = "agentEnableDexAbstraction")] V72, #[serde(rename = "userDexAbstraction")] V73, #[serde(rename = "borrowLend")] V74, #[serde(rename = "sendToEvmWithData")] V75, #[serde(rename = "userPortfolioMargin")] V76, #[serde(rename = "userSetAbstraction")] V77, #[serde(rename = "agentSetAbstraction")] V78, #[serde(rename = "userOutcome")] V79, #[serde(rename = "gossipPriorityBid")] V80, #[serde(rename = "agentSendAsset")] V81, #[serde(rename = "hip3LiquidatorTransfer")] V82, #[serde(rename = "l1ValidatorVoteBridgeDeposit")] V83, #[serde(rename = "authorizeAqav2Role")] V84, #[serde(rename = "stakingLinkDisableTradingUser")] V85, #[serde(rename = "voteL1Hash")] V86, #[serde(rename = "voteAbciDigest")] V87, #[serde(rename = "activateOutcomeDeployer")] V88, #[serde(rename = "trailingStop")] V89, #[serde(rename = "outcomeDeploy")] V90, #[serde(rename = "cDeposit2")] V91 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum25 { A { x: W3Enum25 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum25 { A(W3Enum25), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum26 { #[serde(rename = "normal")] V0, #[serde(rename = "child")] V1, #[serde(rename = "parent")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum26 { A { x: W3Enum26 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum26 { A(W3Enum26), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum27 { #[serde(rename = "normal")] V0, #[serde(rename = "noCross")] V1, #[serde(rename = "strictIsolated")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum27 { A { x: W3Enum27 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum27 { A(W3Enum27), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum28 { #[serde(rename = "register")] V0, #[serde(rename = "changeProfile")] V1, #[serde(rename = "unregister")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum28 { A { x: W3Enum28 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum28 { A(W3Enum28), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum29 { #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V0, #[serde(rename = "registerQuestionFromTemplate")] V1, #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V2, #[serde(rename = "settleOutcome")] V3, #[serde(rename = "settleQuestion")] V4 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum29 { A { x: W3Enum29 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum29 { A(W3Enum29), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum30 { #[serde(rename = "registerAsset")] V0, #[serde(rename = "registerAsset2")] V1, #[serde(rename = "setOracle")] V2, #[serde(rename = "haltTrading")] V3, #[serde(rename = "insertMarginTable")] V4, #[serde(rename = "setFeeRecipient")] V5, #[serde(rename = "setMarginTableIds")] V6, #[serde(rename = "setOpenInterestCaps")] V7, #[serde(rename = "setFundingMultipliers")] V8, #[serde(rename = "setFundingInterestRates")] V9, #[serde(rename = "setFundingClamps")] V10, #[serde(rename = "setSubDeployers")] V11, #[serde(rename = "setMarginModes")] V12, #[serde(rename = "setDeployerFees")] V13, #[serde(rename = "disableDex")] V14, #[serde(rename = "setPerpAnnotation")] V15, #[serde(rename = "migrateDexQuoteToken")] V16, #[serde(rename = "star")] V17 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum30 { A { x: W3Enum30 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum30 { A(W3Enum30), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum31 { #[serde(rename = "registerToken")] V0, #[serde(rename = "registerToken2")] V1, #[serde(rename = "userGenesis")] V2, #[serde(rename = "genesis")] V3, #[serde(rename = "registerSpot")] V4, #[serde(rename = "registerHyperliquidity")] V5, #[serde(rename = "requestEvmContract")] V6, #[serde(rename = "setFullName")] V7, #[serde(rename = "setTokenAnnotation")] V8, #[serde(rename = "setDeployerTradingFeeShare")] V9, #[serde(rename = "setDeployerLabel")] V10, #[serde(rename = "enableFreezePrivilege")] V11, #[serde(rename = "freezeUser")] V12, #[serde(rename = "revokeFreezePrivilege")] V13, #[serde(rename = "enableQuoteToken")] V14, #[serde(rename = "disableQuoteToken")] V15 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum31 { A { x: W3Enum31 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum31 { A(W3Enum31), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum32 { #[serde(rename = "registerTokensAndStandaloneOutcome")] V0, #[serde(rename = "registerTokensAndQuestion")] V1, #[serde(rename = "settleOutcome")] V2, #[serde(rename = "settleQuestion2")] V3, #[serde(rename = "changeOutcomeDescription")] V4, #[serde(rename = "registerAndAssociateNamedOutcome")] V5, #[serde(rename = "changeQuestionDescription")] V6, #[serde(rename = "registerTemplate")] V7, #[serde(rename = "registerTemplateGroup")] V8, #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V9, #[serde(rename = "registerQuestionFromTemplate")] V10, #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V11, #[serde(rename = "setSubDeployers")] V12 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum32 { A { x: W3Enum32 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum32 { A(W3Enum32), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum33 { #[serde(rename = "splitOutcome")] V0, #[serde(rename = "mergeOutcome")] V1, #[serde(rename = "mergeQuestion")] V2, #[serde(rename = "negateOutcome")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum33 { A { x: W3Enum33 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum33 { A(W3Enum33), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum34 { #[serde(rename = "standaloneOutcome")] V0, #[serde(rename = "question")] V1, #[serde(rename = "questionOutcome")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum34 { A { x: W3Enum34 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum34 { A(W3Enum34), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum35 { #[serde(rename = "technical")] V0, #[serde(rename = "treasury")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum35 { A { x: W3Enum35 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum35 { A(W3Enum35), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum36 { #[serde(rename = "toggleSpotDusting")] V0 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum36 { A { x: W3Enum36 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum36 { A(W3Enum36), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum37 { #[serde(rename = "tp")] V0, #[serde(rename = "sl")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum37 { A { x: W3Enum37 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum37 { A(W3Enum37), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum38 { #[serde(rename = "unjailSelf")] V0, #[serde(rename = "jailSelf")] V1, #[serde(rename = "voteJail")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum38 { A { x: W3Enum38 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum38 { A(W3Enum38), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum39 { #[serde(rename = "usdtUsdcPx")] V0, #[serde(rename = "nativePx")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum39 { A { x: W3Enum39 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum39 { A(W3Enum39), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum40 { #[serde(rename = "yes")] V0, #[serde(rename = "no")] V1, #[serde(rename = "abstain")] V2 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum40 { A { x: W3Enum40 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum40 { A(W3Enum40), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum41 { #[serde(rename = "registerAsset")] V0, #[serde(rename = "setOracle")] V1, #[serde(rename = "insertMarginTable")] V2, #[serde(rename = "setFeeRecipient")] V3, #[serde(rename = "haltTrading")] V4, #[serde(rename = "setMarginTableIds")] V5, #[serde(rename = "setOpenInterestCaps")] V6, #[serde(rename = "setFundingMultipliers")] V7, #[serde(rename = "setMarginModes")] V8, #[serde(rename = "setDeployerFees")] V9, #[serde(rename = "setFeeScale")] V10, #[serde(rename = "setFundingInterestRates")] V11, #[serde(rename = "disableDex")] V12, #[serde(rename = "setPerpAnnotation")] V13, #[serde(rename = "migrateDexQuoteToken")] V14, #[serde(rename = "setFundingClamps")] V15, #[serde(rename = "hip3Star")] V16 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum41 { A { x: W3Enum41 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum41 { A(W3Enum41), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum42 { #[serde(rename = "l")] V0, #[serde(rename = "limit")] V1, #[serde(rename = "m")] V2, #[serde(rename = "market")] V3, #[serde(rename = "T")] V4, #[serde(rename = "takeProfitMarket")] V5, #[serde(rename = "t")] V6, #[serde(rename = "takeProfitLimit")] V7, #[serde(rename = "S")] V8, #[serde(rename = "stopMarket")] V9, #[serde(rename = "s")] V10, #[serde(rename = "stopLimit")] V11, #[serde(rename = "closeForVaultWithdrawal")] V12, #[serde(rename = "v")] V13, #[serde(rename = "d")] V14, #[serde(rename = "spotDustConversion")] V15, #[serde(rename = "b")] V16, #[serde(rename = "borrowLendLiquidation")] V17, #[serde(rename = "twapSlice")] V18, #[serde(rename = "w")] V19, #[serde(rename = "trailingStopMarket")] V20, #[serde(rename = "z")] V21 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum42 { A { x: W3Enum42 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum42 { A(W3Enum42), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum43 { #[serde(rename = "Ec")] V0, #[serde(rename = "DummyTokyo")] V1, #[serde(rename = "DummyTokyo2")] V2, #[serde(rename = "GaOnchain")] V3, #[serde(rename = "GbOnchain")] V4, #[serde(rename = "NodeTestnet")] V5, #[serde(rename = "NodeTestnet2")] V6, #[serde(rename = "NodeTestnet3")] V7, #[serde(rename = "NodeTestnet4")] V8, #[serde(rename = "Ea")] V9, #[serde(rename = "Ea2")] V10, #[serde(rename = "Ea3")] V11, #[serde(rename = "EaMm")] V12, #[serde(rename = "EaTx")] V13, #[serde(rename = "HeavyTestnet")] V14, #[serde(rename = "HeavyMainnet")] V15, #[serde(rename = "Eb")] V16, #[serde(rename = "Ed")] V17, #[serde(rename = "Ee")] V18, #[serde(rename = "SoloTestnet")] V19, #[serde(rename = "SoloMainnet")] V20, #[serde(rename = "LockerTestnet")] V21, #[serde(rename = "LockerMainnet")] V22, #[serde(rename = "RpcTestnet")] V23, #[serde(rename = "RpcSandbox")] V24, #[serde(rename = "RpcMainnet")] V25, #[serde(rename = "RpcMainnet2")] V26, #[serde(rename = "Sa")] V27, #[serde(rename = "Sb")] V28, #[serde(rename = "Sc")] V29, #[serde(rename = "Sd")] V30, #[serde(rename = "WebSandbox")] V31, #[serde(rename = "SoloSandbox")] V32, #[serde(rename = "NvTestnet")] V33, #[serde(rename = "NvTestnet2")] V34, #[serde(rename = "NvMainnet")] V35, #[serde(rename = "NvMainnet2")] V36, #[serde(rename = "NvMainnet3")] V37, #[serde(rename = "JoinMainnet")] V38, #[serde(rename = "DummyNv")] V39, #[serde(rename = "FBinSpot")] V40, #[serde(rename = "FBinSpot2")] V41, #[serde(rename = "FBinSpot3")] V42, #[serde(rename = "FBinSpot4")] V43, #[serde(rename = "FBinSpot5")] V44, #[serde(rename = "FBinSpot6")] V45, #[serde(rename = "FBinSpot7")] V46, #[serde(rename = "FBinSpot8")] V47, #[serde(rename = "FBinPerp")] V48, #[serde(rename = "FBinPerp2")] V49, #[serde(rename = "FOkexSpot")] V50, #[serde(rename = "FOkexSpot2")] V51, #[serde(rename = "FOkexPerp")] V52, #[serde(rename = "FHuobiSpot")] V53, #[serde(rename = "FHuobiSpot2")] V54, #[serde(rename = "FHuobiSpot3")] V55, #[serde(rename = "FHuobiSpot4")] V56, #[serde(rename = "FHuobiPi")] V57, #[serde(rename = "FHuobiPerp")] V58, #[serde(rename = "FCobSpot")] V59, #[serde(rename = "FKraSpot")] V60, #[serde(rename = "FBybitSpot")] V61, #[serde(rename = "ScratchDummy")] V62, #[serde(rename = "ScratchCron")] V63, #[serde(rename = "OBinSpot")] V64, #[serde(rename = "FHlPerp")] V65, #[serde(rename = "GaHlPerp")] V66, #[serde(rename = "GaHlPerp2")] V67, #[serde(rename = "GaHlPerp3")] V68, #[serde(rename = "GbHlPerp")] V69, #[serde(rename = "GbHlPerp2")] V70, #[serde(rename = "GbHlPerp3")] V71, #[serde(rename = "GcHlPerp")] V72, #[serde(rename = "GcHlPerp2")] V73, #[serde(rename = "GdHlPerp")] V74, #[serde(rename = "GdHlPerp2")] V75, #[serde(rename = "GsHlPerp")] V76, #[serde(rename = "EaHlPerp")] V77, #[serde(rename = "EbHlPerp")] V78 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum43 { A { x: W3Enum43 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum43 { A(W3Enum43), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum44 { #[serde(rename = "d")] V0, #[serde(rename = "default")] V1, #[serde(rename = "dexAbstraction")] V2, #[serde(rename = "e")] V3, #[serde(rename = "disabled")] V4, #[serde(rename = "i")] V5, #[serde(rename = "z")] V6, #[serde(rename = "u")] V7, #[serde(rename = "unifiedAccount")] V8, #[serde(rename = "p")] V9, #[serde(rename = "portfolioMargin")] V10 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum44 { A { x: W3Enum44 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum44 { A(W3Enum44), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum45 { #[serde(rename = "C")] V0, #[serde(rename = "Cross")] V1, #[serde(rename = "I")] V2, #[serde(rename = "Isolated")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum45 { A { x: W3Enum45 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum45 { A(W3Enum45), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum46 { #[serde(rename = "activate")] V0, #[serde(rename = "deactivate")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum46 { A { x: W3Enum46 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum46 { A(W3Enum46), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum47 { #[serde(rename = "proxy")] V0, #[serde(rename = "setOracle")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum47 { A { x: W3Enum47 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum47 { A(W3Enum47), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum48 { #[serde(rename = "hex")] V0, #[serde(rename = "base58")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum48 { A { x: W3Enum48 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum48 { A(W3Enum48), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum49 { #[serde(rename = "Enabled")] V0, #[serde(rename = "Disabled")] V1 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum49 { A { x: W3Enum49 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum49 { A(W3Enum49), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum50 { #[serde(rename = "bridge-voter")] V0, #[serde(rename = "reference-oracle-publisher")] V1, #[serde(rename = "outcome-voter")] V2, #[serde(rename = "visor")] V3 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum50 { A { x: W3Enum50 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum50 { A(W3Enum50), B(u64) }
#[derive(Deserialize, Debug)]
enum W3Enum51 { #[serde(rename = "NodeMetadata")] V0, #[serde(rename = "VisorMetadata")] V1, #[serde(rename = "HotfixMetadata")] V2, #[serde(rename = "NodeArtifact")] V3, #[serde(rename = "PublisherBinaryMetadata")] V4 }
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3Enum51 { A { x: W3Enum51 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3Enum51 { A(W3Enum51), B(u64) }
#[derive(Deserialize, Debug)]
enum W3AliasEnum0 {
    #[serde(rename = "l", alias = "limit")] V0,
    #[serde(rename = "m", alias = "market")] V1,
    #[serde(rename = "T", alias = "takeProfitMarket")] V2,
    #[serde(rename = "t", alias = "takeProfitLimit")] V3,
    #[serde(rename = "S", alias = "stopMarket")] V4,
    #[serde(rename = "s", alias = "stopLimit")] V5,
    #[serde(rename = "closeForVaultWithdrawal", alias = "v")] V6,
    #[serde(rename = "d", alias = "spotDustConversion")] V7,
    #[serde(rename = "b", alias = "borrowLendLiquidation")] V8,
    #[serde(rename = "twapSlice", alias = "w")] V9,
    #[serde(rename = "trailingStopMarket", alias = "z")] V10,
}
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3AliasEnum0 { A { x: W3AliasEnum0 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3AliasEnum0 { A(W3AliasEnum0), B(u64) }
#[derive(Deserialize, Debug)]
enum W3AliasEnum1 {
    #[serde(rename = "d", alias = "default", alias = "dexAbstraction", alias = "e")] V0,
    #[serde(rename = "disabled", alias = "i")] V1,
    #[serde(rename = "z")] V2,
    #[serde(rename = "u", alias = "unifiedAccount")] V3,
    #[serde(rename = "p", alias = "portfolioMargin")] V4,
}
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3AliasEnum1 { A { x: W3AliasEnum1 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3AliasEnum1 { A(W3AliasEnum1), B(u64) }
#[derive(Deserialize, Debug)]
enum W3AliasEnum2 {
    #[serde(rename = "C", alias = "Cross")] V0,
    #[serde(rename = "I", alias = "Isolated")] V1,
}
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3AliasEnum2 { A { x: W3AliasEnum2 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3AliasEnum2 { A(W3AliasEnum2), B(u64) }
#[derive(Deserialize, Debug)]
enum W3AliasEnum3 {
    #[serde(rename = "registerToken")] V0,
    #[serde(rename = "registerToken2")] V1,
    #[serde(rename = "userGenesis")] V2,
    #[serde(rename = "genesis")] V3,
    #[serde(rename = "registerSpot")] V4,
    #[serde(rename = "registerHyperliquidity")] V5,
    #[serde(rename = "requestEvmContract")] V6,
    #[serde(rename = "setFullName")] V7,
    #[serde(rename = "setTokenAnnotation")] V8,
    #[serde(rename = "setDeployerTradingFeeShare")] V9,
    #[serde(rename = "setDeployerLabel")] V10,
    #[serde(rename = "enableFreezePrivilege")] V11,
    #[serde(rename = "freezeUser")] V12,
    #[serde(rename = "revokeFreezePrivilege")] V13,
    #[serde(rename = "enableQuoteToken")] V14,
    #[serde(rename = "disableQuoteToken")] V15,
}
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3AliasEnum3 { A { x: W3AliasEnum3 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3AliasEnum3 { A(W3AliasEnum3), B(u64) }
#[derive(Deserialize, Debug)]
enum W3AliasEnum4 {
    #[serde(rename = "registerAsset")] V0,
    #[serde(rename = "registerAsset2")] V1,
    #[serde(rename = "setOracle")] V2,
    #[serde(rename = "haltTrading")] V3,
    #[serde(rename = "insertMarginTable")] V4,
    #[serde(rename = "setFeeRecipient")] V5,
    #[serde(rename = "setMarginTableIds")] V6,
    #[serde(rename = "setOpenInterestCaps")] V7,
    #[serde(rename = "setFundingMultipliers")] V8,
    #[serde(rename = "setFundingInterestRates")] V9,
    #[serde(rename = "setFundingClamps")] V10,
    #[serde(rename = "setSubDeployers")] V11,
    #[serde(rename = "setMarginModes")] V12,
    #[serde(rename = "setDeployerFees")] V13,
    #[serde(rename = "disableDex")] V14,
    #[serde(rename = "setPerpAnnotation")] V15,
    #[serde(rename = "migrateDexQuoteToken")] V16,
    #[serde(rename = "star")] V17,
}
#[derive(Deserialize, Debug)] #[serde(tag = "type")] enum TagW3AliasEnum4 { A { x: W3AliasEnum4 } }
#[derive(Deserialize, Debug)] #[serde(untagged)] enum UntagW3AliasEnum4 { A(W3AliasEnum4), B(u64) }
#[inline(never)]
fn drive_compact_0(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum0>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum1>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum2>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct2>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum3>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct3>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum4>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum4>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum4>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct4>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum5>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum5>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum5>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct5>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum6>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum6>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum6>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct6>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum7>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum7>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum7>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct7>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum8>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum8>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum8>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct8>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum9>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum9>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum9>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct9>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum10>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum10>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum10>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct10>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum11>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum11>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum11>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct11>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct11>(b));
}
#[inline(never)]
fn drive_compact_12(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum12>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum12>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum12>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct12>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum13>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum13>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum13>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct13>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum14>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum14>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum14>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct14>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum15>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum15>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum15>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct15>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum16>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum16>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum16>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct16>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum17>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum17>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum17>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum17>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct17>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct17>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum18>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum18>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum18>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum18>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct18>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct18>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum19>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum19>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum19>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum19>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct19>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct19>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum20>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum20>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum20>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum20>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct20>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct20>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum21>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum21>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum21>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum21>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct21>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct21>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum22>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum22>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum22>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum22>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct22>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct22>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum23>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum23>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum23>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum23>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct23>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct23>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct23>(b));
}
#[inline(never)]
fn drive_compact_24(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum24>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum24>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum24>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum24>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct24>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct24>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum25>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum25>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum25>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum25>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct25>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct25>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum26>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum26>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum26>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum26>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct26>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct26>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum27>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum27>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum27>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum27>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct27>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct27>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum28>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum28>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum28>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum28>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct28>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct28>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum29>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum29>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum29>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum29>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct29>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct29>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum30>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum30>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum30>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum30>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct30>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct30>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum31>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum31>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum31>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum31>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct31>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct31>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum32>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum32>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum32>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum32>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct32>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct32>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum33>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum33>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum33>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum33>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct33>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct33>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum34>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum34>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum34>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum34>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct34>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct34>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactEnum35>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactEnum35>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<CompactEnum35>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactEnum35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactEnum35>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagCompactEnum35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagCompactEnum35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<CompactStruct35>(b));
    let _ = core::hint::black_box(serde_json::from_str::<CompactStruct35>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagCompactStruct35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagCompactStruct35>(b));
}
#[inline(never)]
fn drive_w3e_0(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum0>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum1>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum2>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum3>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum4>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum4>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum4>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum5>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum5>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum5>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum6>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum6>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum6>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum7>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum7>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum7>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum8>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum8>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum8>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum9>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum9>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum9>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum10>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum10>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum10>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum11>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum11>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum11>(b));
}
#[inline(never)]
fn drive_w3e_12(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum12>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum12>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum12>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum13>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum13>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum13>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum14>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum14>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum14>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum15>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum15>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum15>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum16>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum16>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum16>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum17>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum17>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum17>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum17>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum18>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum18>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum18>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum18>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum19>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum19>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum19>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum19>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum20>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum20>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum20>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum20>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum21>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum21>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum21>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum21>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum22>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum22>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum22>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum22>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum23>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum23>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum23>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum23>(b));
}
#[inline(never)]
fn drive_w3e_24(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum24>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum24>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum24>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum24>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum25>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum25>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum25>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum25>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum26>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum26>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum26>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum26>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum27>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum27>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum27>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum27>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum28>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum28>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum28>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum28>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum29>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum29>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum29>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum29>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum30>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum30>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum30>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum30>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum31>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum31>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum31>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum31>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum32>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum32>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum32>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum32>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum33>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum33>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum33>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum33>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum34>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum34>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum34>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum34>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum35>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum35>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum35>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum35>(b));
}
#[inline(never)]
fn drive_w3e_36(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum36>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum36>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum36>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum36>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum36>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum36>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum37>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum37>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum37>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum37>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum37>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum37>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum38>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum38>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum38>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum38>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum38>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum38>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum39>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum39>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum39>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum39>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum39>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum39>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum40>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum40>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum40>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum40>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum40>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum40>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum41>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum41>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum41>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum41>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum41>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum41>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum42>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum42>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum42>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum42>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum42>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum42>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum43>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum43>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum43>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum43>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum43>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum43>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum44>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum44>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum44>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum44>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum44>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum44>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum45>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum45>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum45>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum45>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum45>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum45>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum46>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum46>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum46>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum46>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum46>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum46>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum47>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum47>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum47>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum47>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum47>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum47>(b));
}
#[inline(never)]
fn drive_w3e_48(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum48>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum48>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum48>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum48>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum48>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum48>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum49>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum49>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum49>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum49>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum49>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum49>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum50>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum50>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum50>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum50>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum50>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum50>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3Enum51>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3Enum51>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3Enum51>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3Enum51>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3Enum51>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3Enum51>(b));
}
#[inline(never)]
fn drive_w3a(s: &str, b: &[u8]) {
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3AliasEnum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3AliasEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3AliasEnum0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3AliasEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3AliasEnum0>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3AliasEnum0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3AliasEnum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3AliasEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3AliasEnum1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3AliasEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3AliasEnum1>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3AliasEnum1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3AliasEnum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3AliasEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3AliasEnum2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3AliasEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3AliasEnum2>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3AliasEnum2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3AliasEnum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3AliasEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3AliasEnum3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3AliasEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3AliasEnum3>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3AliasEnum3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<TagW3AliasEnum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagW3AliasEnum4>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<UntagW3AliasEnum4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<UntagW3AliasEnum4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<W3AliasEnum4>(s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<W3AliasEnum4>(b));
}
fn main() {
    let s = std::env::args().nth(1).unwrap_or_default();
    let b = s.as_bytes();
    drive_compact_0(&s, b);
    drive_compact_12(&s, b);
    drive_compact_24(&s, b);
    drive_w3e_0(&s, b);
    drive_w3e_12(&s, b);
    drive_w3e_24(&s, b);
    drive_w3e_36(&s, b);
    drive_w3e_48(&s, b);
    drive_w3a(&s, b);
}
