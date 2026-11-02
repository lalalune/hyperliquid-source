use node115_snapshot_selectors::{
    mode_gate_opens, outer_selection, selected_exit_prefix, worker_admission, ExitPrefix,
    OuterPath, WorkerAdmission, WrapperKind,
};
use std::io::{self, BufRead};
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

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('\t').collect();
        println!("{}", classify(&fields));
    }
}
