use node115_replica_line_count::{CountError, line_count};
use std::io::{self, Write};
use std::num::IntErrorKind;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Output, Stdio};

fn output(bytes: &[u8], code: i32) -> io::Result<Output> {
    Ok(Output {
        stdout: bytes.to_vec(),
        stderr: b"ignored on success".to_vec(),
        status: ExitStatus::from_raw(code << 8),
    })
}

#[test]
fn preserves_gate_order_and_distinguishes_zero_from_no_token() {
    assert!(matches!(
        line_count(Err(io::Error::from(io::ErrorKind::NotFound))),
        Err(CountError::Launch(_))
    ));
    assert!(
        matches!(line_count(output(b"3\xff", 2)),Err(CountError::Status(status)) if status.code()==Some(2))
    );
    assert!(
        matches!(line_count(output(&[b'3',b' ',0xf0,0x9f], 0)), Err(CountError::Encoding(e)) if e.valid_up_to()==2 && e.error_len().is_none())
    );
    for text in ["", " \n\t\u{205f}"] {
        assert!(matches!(
            line_count(output(text.as_bytes(), 0)),
            Err(CountError::EmptyOutput)
        ));
    }
    assert_eq!(line_count(output(b" 0000 file", 0)).unwrap(), 0);
}

#[test]
fn matches_token_boundaries_and_decimal_overflow() {
    for text in [
        "\u{1680}\u{200a}+42\u{a0}path",
        "42",
        "0000000000000000042\tfoo",
    ] {
        assert_eq!(line_count(output(text.as_bytes(), 0)).unwrap(), 42);
    }
    for text in [
        "\u{1c}42",
        "42\u{200b}foo",
        "-1",
        "+ path",
        "foo 42",
        "４２",
    ] {
        assert!(matches!(
            line_count(output(text.as_bytes(), 0)),
            Err(CountError::Count(_))
        ));
    }
    assert_eq!(
        line_count(output(b"+18446744073709551615 f", 0)).unwrap(),
        u64::MAX
    );
    assert!(
        matches!(line_count(output(b"18446744073709551616 f",0)),Err(CountError::Count(e)) if e.kind()==&IntErrorKind::PosOverflow)
    );
}

#[test]
fn reads_output_from_the_host_wc_utility() {
    let mut child = Command::new("wc")
        .arg("-l")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"a\n\npartial")
        .unwrap();
    assert_eq!(line_count(child.wait_with_output()).unwrap(), 2);
}

#[test]
fn host_token_delimiters_match_the_target_table_for_every_scalar() {
    for c in (0..=0x10ffff).filter_map(char::from_u32) {
        let native = matches!(u32::from(c),
            0x09..=0x0d | 0x20 | 0x85 | 0xa0 | 0x1680 |
            0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000);
        assert_eq!(c.is_whitespace(), native, "U+{:04X}", u32::from(c));
    }
}

#[test]
fn reads_a_named_regular_file_with_spaces_and_a_trailing_partial_line() {
    use std::fs;
    let path = std::env::temp_dir().join(format!("node115 wc output {}.txt", std::process::id()));
    let mut file = fs::File::create_new(&path).unwrap();
    file.write_all(b"first\n\nunfinished").unwrap();
    drop(file);
    let result = Command::new("wc")
        .arg("-l")
        .arg(&path)
        .env("LC_ALL", "C")
        .output();
    fs::remove_file(path).unwrap();
    assert_eq!(line_count(result).unwrap(), 2);
}
