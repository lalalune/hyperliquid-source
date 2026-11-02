// Input-only TH01 adapter to the real crate. No expected values or target evidence.
use node94_consensus_admission::request_throttle::{
    RequestKey, RequestRow, RequestThrottle, RequestTimestamp, ThrottleOutcome,
};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{self, Read, Write};

type Result<T> = std::result::Result<T, &'static str>;
struct Frame<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Frame<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.at.checked_add(N).ok_or("length")?;
        let data = self.bytes.get(self.at..end).ok_or("short frame")?;
        self.at = end;
        data.try_into().map_err(|_| "width")
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn time(&mut self) -> Result<RequestTimestamp> {
        Ok(RequestTimestamp {
            packed_date: i32::from_le_bytes(self.take()?),
            second: self.u32()?,
            nano: self.u32()?,
        })
    }
    fn key(&mut self) -> Result<RequestKey> {
        Ok(RequestKey {
            round: self.u64()?,
            hash: self.take()?,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 || text.len() > 4_194_304 {
        return Err("hex length");
    }
    fn digit(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("hex digit"),
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect()
}
fn timestamp(t: RequestTimestamp) -> String {
    format!("[{},{},{}]", t.packed_date, t.second, t.nano)
}
fn snapshot(state: &RequestThrottle) -> String {
    let rows = state.snapshot();
    let mut text = String::from("[");
    for (index, row) in rows.iter().enumerate() {
        if index != 0 {
            text.push(',');
        }
        write!(text, "{{\"hash\":\"{}\",\"reasons\":[", hex(&row.key.hash)).unwrap();
        for (i, reason) in row.reasons.iter().enumerate() {
            if i != 0 {
                text.push(',');
            }
            write!(text, "{reason}").unwrap();
        }
        write!(
            text,
            "],\"round\":{},\"sent\":{},\"stamp\":{}}}",
            row.key.round,
            row.sent,
            timestamp(row.stamp)
        )
        .unwrap();
    }
    text.push(']');
    text
}
fn history(bytes: &[u8]) -> Result<String> {
    let mut frame = Frame { bytes, at: 0 };
    if frame.take::<4>()? != *b"TH01" {
        return Err("magic");
    }
    let initial_count = frame.u32()?;
    if initial_count > 4096 {
        return Err("initial count policy");
    }
    let mut rows = Vec::new();
    for _ in 0..initial_count {
        let key = frame.key()?;
        let stamp = frame.time()?;
        let sent = match frame.u8()? {
            0 => false,
            1 => true,
            _ => return Err("sent bool"),
        };
        let count = frame.u16()?;
        if count > 256 {
            return Err("reason count");
        }
        let mut reasons = BTreeSet::new();
        let mut previous = None;
        for _ in 0..count {
            let reason = frame.u8()?;
            if previous.is_some_and(|p| p >= reason) {
                return Err("reason order");
            }
            previous = Some(reason);
            reasons.insert(reason);
        }
        rows.push(RequestRow {
            key,
            stamp,
            reasons,
            sent,
        });
    }
    let mut state = RequestThrottle::from_rows(rows).map_err(|_| "initial state")?;
    let steps = frame.u32()?;
    if steps > 4096 || u64::from(steps) * u64::from(initial_count + steps) > 1_000_000 {
        return Err("step work policy");
    }
    let mut text = String::from("[");
    for index in 0..steps {
        let key = frame.key()?;
        let time = frame.time()?;
        let reason = frame.u8()?;
        let delay = match frame.u8()? {
            0 => None,
            1 => Some(frame.u64()?),
            _ => return Err("delay option"),
        };
        let result = state.consider(key, time, reason, delay);
        if index != 0 {
            text.push(',');
        }
        let (registered, deadline, request, status) = match result {
            ThrottleOutcome::InvalidTime => {
                write!(
                    text,
                    "{{\"snapshot\":{},\"status\":\"invalid_time\"}}",
                    snapshot(&state)
                )
                .unwrap();
                continue;
            }
            ThrottleOutcome::DeadlineRange { registered } => (
                registered,
                "null".to_owned(),
                "null".to_owned(),
                "deadline_range",
            ),
            ThrottleOutcome::Held {
                registered,
                deadline,
            } => (registered, timestamp(deadline), "null".to_owned(), "held"),
            ThrottleOutcome::Request {
                registered,
                deadline,
                key,
            } => (
                registered,
                timestamp(deadline),
                format!("[{},\"{}\"]", key.round, hex(&key.hash)),
                "request",
            ),
        };
        write!(text, "{{\"deadline\":{deadline},\"registered\":{registered},\"request\":{request},\"snapshot\":{},\"status\":\"{status}\"}}", snapshot(&state)).unwrap();
    }
    if frame.at != bytes.len() {
        return Err("trailing frame");
    }
    text.push(']');
    Ok(text)
}

fn run() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("arguments");
    }
    let mut raw = Vec::new();
    io::stdin()
        .take(33_554_433)
        .read_to_end(&mut raw)
        .map_err(|_| "input read")?;
    if raw.len() > 33_554_432 {
        return Err("input size policy");
    }
    if raw.is_empty() {
        return Ok(());
    }
    let input = std::str::from_utf8(&raw).map_err(|_| "utf8")?;
    if !input.ends_with('\n') {
        return Err("line termination");
    }
    let mut output = String::new();
    for line in input.split_terminator('\n') {
        let (id, data) = line.split_once('\t').ok_or("line fields")?;
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|x| x.is_ascii_alphanumeric() || x == b'_' || x == b'-')
        {
            return Err("id");
        }
        let answer = history(&unhex(data)?)?;
        writeln!(output, "{id}\t{answer}").unwrap();
        if output.len() > 134_217_728 {
            return Err("output size policy");
        }
    }
    io::stdout()
        .write_all(output.as_bytes())
        .map_err(|_| "output write")
}

fn main() {
    if let Err(error) = run() {
        eprintln!("request-throttle client: {error}");
        std::process::exit(2);
    }
}
