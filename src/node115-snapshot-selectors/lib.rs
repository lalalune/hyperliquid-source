//! Selected node115 snapshot routes; no collection, callback or request API.
#![no_std]
#![forbid(unsafe_code)]

const ALL: u64 = 1 << 63;
const SPECIAL: u64 = ALL + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerAdmission {
    AllCollection,
    LimitExit,
    Explicit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapperKind {
    First,
    Second,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OuterPath {
    Special,
    Worker0,
    Worker1,
    Worker2,
    Worker3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OuterSelection {
    pub path: OuterPath,
    pub normalized_mode: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitPrefix {
    KnownSelectedReturn,
    OtherUnclosedRoute,
}

pub fn worker_admission(selector: u64, count: u64) -> WorkerAdmission {
    if selector == ALL {
        WorkerAdmission::AllCollection
    } else if count >= 101 {
        WorkerAdmission::LimitExit
    } else {
        WorkerAdmission::Explicit
    }
}

pub fn outer_selection(
    which: WrapperKind,
    selector: u64,
    selector_byte: u8,
    raw_mode: u64,
) -> OuterSelection {
    let normalized_mode = u64::from(raw_mode as u32 != 0);
    let nonzero = selector_byte != 0;
    let path = if selector == SPECIAL {
        OuterPath::Special
    } else {
        match (which, nonzero) {
            (WrapperKind::First, true) => OuterPath::Worker0,
            (WrapperKind::First, false) => OuterPath::Worker2,
            (WrapperKind::Second, true) => OuterPath::Worker3,
            (WrapperKind::Second, false) => OuterPath::Worker1,
        }
    };
    OuterSelection {
        path,
        normalized_mode,
    }
}

pub fn mode_gate_opens(mode: u64) -> bool {
    mode == 1
}

/// Only the measured positive guard. Other routes may also return; they are unclosed.
pub fn selected_exit_prefix(tag: u16) -> ExitPrefix {
    if (266..=351).contains(&tag) {
        ExitPrefix::KnownSelectedReturn
    } else {
        ExitPrefix::OtherUnclosedRoute
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    fn classify(f: &[&str]) -> std::string::String {
        match f[0] {
            "W" => {
                assert_eq!(f.len(), 4);
                let owner: u8 = f[1].parse().unwrap();
                assert!(owner < 4);
                match worker_admission(f[2].parse().unwrap(), f[3].parse().unwrap()) {
                    WorkerAdmission::AllCollection => "A".into(),
                    WorkerAdmission::LimitExit => "L".into(),
                    WorkerAdmission::Explicit => "E".into(),
                }
            }
            "O" => {
                assert_eq!(f.len(), 5);
                let index: usize = f[1].parse().unwrap();
                let which = [WrapperKind::First, WrapperKind::Second][index];
                let selected = outer_selection(
                    which,
                    f[2].parse().unwrap(),
                    f[3].parse().unwrap(),
                    f[4].parse().unwrap(),
                );
                let code = match selected.path {
                    OuterPath::Special => 4,
                    OuterPath::Worker0 => 0,
                    OuterPath::Worker1 => 1,
                    OuterPath::Worker2 => 2,
                    OuterPath::Worker3 => 3,
                };
                std::format!("{}\t{}", code, selected.normalized_mode)
            }
            "M" => {
                assert_eq!(f.len(), 3);
                let owner: u8 = f[1].parse().unwrap();
                assert!(owner < 4);
                std::format!("{}", u8::from(mode_gate_opens(f[2].parse().unwrap())))
            }
            "X" => {
                assert_eq!(f.len(), 2);
                match selected_exit_prefix(f[1].parse().unwrap()) {
                    ExitPrefix::KnownSelectedReturn => "K".into(),
                    ExitPrefix::OtherUnclosedRoute => "U".into(),
                }
            }
            _ => panic!("unknown input operation"),
        }
    }

    #[test]
    fn target_smoke_rows() {
        for line in include_str!("target-smoke.tsv").lines() {
            let f: Vec<_> = line.split('\t').collect();
            let n = match f[0] {
                "W" => 4,
                "O" => 5,
                "M" => 3,
                "X" => 2,
                _ => panic!("operation"),
            };
            assert_eq!(classify(&f[..n]), f[n..].join("\t"), "{line}");
        }
    }
}
