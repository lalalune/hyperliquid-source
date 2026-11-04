use node115_command_construction::Command;
use std::io::{self, BufRead};
fn bytes(s: &str) -> Vec<u8> {
    if s == "-" {
        vec![]
    } else {
        s.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let p: Vec<_> = line.split('\t').collect();
        let input = bytes(p[0]);
        let mut cmd = Command::new(&input);
        if p[1] != "~" {
            for arg in p[1].split(';') {
                cmd.push_argument(&bytes(arg));
            }
        }
        let args = cmd.arguments_with_nul();
        assert_eq!(cmd.argv().len(), args.len() + 1);
        assert!(cmd.argv().last().unwrap().is_null());
        assert_ne!(cmd.program_with_nul().as_ptr(), args[0].as_ptr());
        assert_eq!(cmd.program_with_nul(), args[0]);
        for (arg, pointer) in args.iter().zip(cmd.argv()) {
            assert_eq!(arg.as_ptr(), *pointer);
            assert_eq!(arg.last(), Some(&0));
            assert!(!arg[..arg.len() - 1].contains(&0));
        }
        println!(
            "{}|{}|{}|{}|{}",
            cmd.program_kind_raw(),
            u8::from(cmd.saw_nul()),
            hex(cmd.program_with_nul()),
            args.iter().map(|a| hex(a)).collect::<Vec<_>>().join(","),
            cmd.argv().len()
        );
    }
}
