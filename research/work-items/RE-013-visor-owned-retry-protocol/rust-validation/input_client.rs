//! Input-only resource observer. No expectations, case names or target code.
#![forbid(unsafe_code)]
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::rc::{Rc, Weak};
use visor_retry_protocol::{RetryOutcome, SleepRefusal, SleepReply, retry, retry_owned};

type Shared = Rc<RefCell<Observer>>;
#[derive(Default)]
struct Observer {
    trace: Vec<String>,
    attempt_index: usize,
    sleep_index: usize,
    error_serial: u64,
    prior: Option<Weak<ErrorValue>>,
    terminal: Option<Weak<TerminalValue>>,
}
struct Value {
    label: u64,
    bytes: Vec<u8>,
    drop_kind: Option<&'static str>,
    shared: Shared,
}
impl Drop for Value {
    fn drop(&mut self) {
        if let Some(kind) = self.drop_kind {
            self.shared.borrow_mut().trace.push(format!(
                "[\"drop_{kind}\",{},\"{}\"]",
                self.label,
                hex(&self.bytes)
            ));
        }
    }
}
struct ErrorValue {
    serial: u64,
    label: u64,
    shared: Shared,
}
impl Drop for ErrorValue {
    fn drop(&mut self) {
        self.shared
            .borrow_mut()
            .trace
            .push(format!("[\"drop_error\",{},{}]", self.serial, self.label));
    }
}
struct TerminalValue {
    label: u64,
    shared: Shared,
}
impl Drop for TerminalValue {
    fn drop(&mut self) {
        // A premature drop stays visible; the final caller drop occurs only
        // after output is captured and is outside the operation boundary.
        self.shared
            .borrow_mut()
            .trace
            .push(format!("[\"drop_terminal\",{}]", self.label));
    }
}
struct CleanupError {
    label: u64,
    shared: Shared,
}
impl Drop for CleanupError {
    fn drop(&mut self) {
        self.shared
            .borrow_mut()
            .trace
            .push(format!("[\"drop_cleanup_error\",{}]", self.label));
    }
}
struct Frame {
    owned: bool,
    request_label: u64,
    request: Vec<u8>,
    terminal_label: u64,
    description: String,
    delays: Option<Vec<u64>>,
    cleanup: Option<(u64, Vec<u8>)>,
    cleanup_error: Option<u64>,
    attempts: Vec<Option<u64>>,
    sleeps: Vec<SleepReply>,
}
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.bytes.len() - self.pos {
            return Err("truncated frame".into());
        }
        let value = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| "u32")?,
        ))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| "u64")?,
        ))
    }
    fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| "i32")?,
        ))
    }
    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| "i64")?,
        ))
    }
    fn option(&mut self) -> Result<bool, String> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("option domain".into()),
        }
    }
    fn count(&mut self, cap: usize) -> Result<usize, String> {
        let n = self.u32()? as usize;
        if n > cap {
            Err("count limit".into())
        } else {
            Ok(n)
        }
    }
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.count(65536)?;
        Ok(self.take(n)?.to_vec())
    }
}
fn decode(bytes: &[u8]) -> Result<Frame, String> {
    if bytes.len() > 1 << 20 {
        return Err("frame limit".into());
    }
    let mut r = Reader { bytes, pos: 0 };
    if r.take(4)? != b"VR01" {
        return Err("magic".into());
    }
    let owned = r.option()?;
    let request_label = r.u64()?;
    let request = r.bytes()?;
    let terminal_label = r.u64()?;
    let mut description = String::new();
    let mut delays = None;
    let mut cleanup = None;
    let mut cleanup_error = None;
    if owned {
        if r.option()? {
            cleanup = Some((r.u64()?, r.bytes()?));
        }
        if r.option()? {
            cleanup_error = Some(r.u64()?);
        }
    } else {
        description = String::from_utf8(r.bytes()?).map_err(|_| "description UTF-8")?;
        if r.option()? {
            let n = r.count(256)?;
            let mut words = Vec::with_capacity(n);
            for _ in 0..n {
                words.push(r.u64()?);
            }
            delays = Some(words);
        }
    }
    let n = r.count(256)?;
    let mut attempts = Vec::with_capacity(n);
    for _ in 0..n {
        attempts.push(if r.option()? { Some(r.u64()?) } else { None });
    }
    let n = r.count(1024)?;
    let mut sleeps = Vec::with_capacity(n);
    for _ in 0..n {
        sleeps.push(SleepReply {
            code: r.i32()?,
            remaining_seconds: r.i64()?,
            remaining_nanoseconds: r.i64()?,
        });
    }
    if r.pos != bytes.len() {
        return Err("trailing frame".into());
    }
    Ok(Frame {
        owned,
        request_label,
        request,
        terminal_label,
        description,
        delays,
        cleanup,
        cleanup_error,
        attempts,
        sleeps,
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn option_bool(value: Option<bool>) -> &'static str {
    match value {
        None => "null",
        Some(true) => "true",
        Some(false) => "false",
    }
}
fn execute(frame: Frame) -> String {
    let shared = Rc::new(RefCell::new(Observer::default()));
    let request = Rc::new(Value {
        label: frame.request_label,
        bytes: frame.request.clone(),
        drop_kind: frame.owned.then_some("command"),
        shared: Rc::clone(&shared),
    });
    let request_witness = Rc::downgrade(&request);
    let cleanup = frame.cleanup.as_ref().map(|(label, bytes)| {
        Rc::new(Value {
            label: *label,
            bytes: bytes.clone(),
            drop_kind: Some("cleanup"),
            shared: Rc::clone(&shared),
        })
    });
    let cleanup_witness = cleanup.as_ref().map(Rc::downgrade);
    let attempt = |value: &Rc<Value>| {
        let mut state = shared.borrow_mut();
        let prior = state.prior.as_ref().map(|w| w.strong_count() > 0);
        state.trace.push(format!(
            "[\"attempt\",{},\"{}\",{},{}]",
            value.label,
            hex(&value.bytes),
            Rc::as_ptr(value) == request_witness.as_ptr(),
            option_bool(prior)
        ));
        let response = frame.attempts.get(state.attempt_index).copied().flatten();
        state.attempt_index += 1;
        if let Some(label) = response {
            let serial = state.error_serial;
            state.error_serial += 1;
            state
                .trace
                .push(format!("[\"create_error\",{serial},{label}]"));
            let error = Rc::new(ErrorValue {
                serial,
                label,
                shared: Rc::clone(&shared),
            });
            state.prior = Some(Rc::downgrade(&error));
            Err(error)
        } else {
            state.trace.push("[\"attempt_success\"]".into());
            Ok(())
        }
    };
    let sleep = |request: visor_retry_protocol::SleepRequest| {
        let mut state = shared.borrow_mut();
        state.trace.push(format!(
            "[\"sleep\",{},{},{},{}]",
            request.seconds(),
            request.nanoseconds(),
            request.clock(),
            request.flags()
        ));
        let reply = frame
            .sleeps
            .get(state.sleep_index)
            .copied()
            .unwrap_or(SleepReply {
                code: 0,
                remaining_seconds: 0,
                remaining_nanoseconds: 0,
            });
        state.sleep_index += 1;
        state.trace.push(format!(
            "[\"sleep_result\",{},{},{}]",
            reply.code, reply.remaining_seconds, reply.remaining_nanoseconds
        ));
        reply
    };
    let terminal = |description: &str, delays: &[u64], error: &Rc<ErrorValue>| {
        let mut state = shared.borrow_mut();
        let alive = state
            .prior
            .as_ref()
            .is_some_and(|w| w.strong_count() > 0 && w.as_ptr() == Rc::as_ptr(error));
        let words = delays
            .iter()
            .map(|b| format!("\"{b:016x}\""))
            .collect::<Vec<_>>()
            .join(",");
        state.trace.push(format!(
            "[\"terminal\",\"{}\",[{}],{},{},{}]",
            hex(description.as_bytes()),
            words,
            error.serial,
            error.label,
            alive
        ));
        state
            .trace
            .push(format!("[\"create_terminal\",{}]", frame.terminal_label));
        let result = Rc::new(TerminalValue {
            label: frame.terminal_label,
            shared: Rc::clone(&shared),
        });
        state.terminal = Some(Rc::downgrade(&result));
        result
    };
    let cleanup_callback = |value: &Rc<Value>| {
        let mut state = shared.borrow_mut();
        let identity = cleanup_witness
            .as_ref()
            .is_some_and(|w| w.as_ptr() == Rc::as_ptr(value));
        let terminal_alive = state.terminal.as_ref().map(|w| w.strong_count() > 0);
        state.trace.push(format!(
            "[\"cleanup\",{},\"{}\",{},{}]",
            value.label,
            hex(&value.bytes),
            identity,
            option_bool(terminal_alive)
        ));
        if let Some(label) = frame.cleanup_error {
            state
                .trace
                .push(format!("[\"create_cleanup_error\",{label}]"));
            Err(CleanupError {
                label,
                shared: Rc::clone(&shared),
            })
        } else {
            Ok(())
        }
    };
    let result = if frame.owned {
        retry_owned(
            request,
            cleanup,
            |value, _option| attempt(value),
            sleep,
            terminal,
            cleanup_callback,
        )
    } else {
        retry(
            &request,
            &frame.description,
            frame.delays.as_deref(),
            attempt,
            sleep,
            terminal,
        )
    };
    let (outcome, code, label, identity) = match &result {
        RetryOutcome::Succeeded => ("succeeded", "null".into(), "null".into(), "null"),
        RetryOutcome::Exhausted(t) => {
            let same = shared
                .borrow()
                .terminal
                .as_ref()
                .is_some_and(|w| w.as_ptr() == Rc::as_ptr(t) && w.strong_count() > 0);
            (
                "exhausted",
                "null".into(),
                t.label.to_string(),
                option_bool(Some(same)),
            )
        }
        RetryOutcome::Refused(SleepRefusal::InvalidRemainder) => {
            ("invalid_remainder", "null".into(), "null".into(), "null")
        }
        RetryOutcome::Refused(SleepRefusal::UnexpectedSleepCode(c)) => (
            "unexpected_sleep_code",
            c.to_string(),
            "null".into(),
            "null",
        ),
    };
    // Freeze the entire operation trace before caller-owned result destruction.
    let output = format!(
        "{{\"code\":{code},\"outcome\":\"{outcome}\",\"terminal\":{label},\"terminal_identity\":{identity},\"trace\":[{}]}}",
        shared.borrow().trace.join(",")
    );
    drop(result);
    output
}
fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("no arguments".into());
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|_| "input UTF-8/read")?;
    if input.is_empty() || !input.ends_with('\n') || input.contains('\r') {
        return Err("canonical nonempty LF batch".into());
    }
    let mut frames = Vec::new();
    let mut ids = BTreeSet::new();
    for line in input[..input.len() - 1].split('\n') {
        let (id, payload) = line.split_once('\t').ok_or("two fields")?;
        if id.len() != 7
            || !id.starts_with('C')
            || !id.as_bytes()[1..].iter().all(u8::is_ascii_digit)
            || !ids.insert(id.to_owned())
        {
            return Err("opaque unique ID".into());
        }
        if payload.is_empty()
            || payload.len() % 2 != 0
            || payload.len() > 2 << 20
            || !payload
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("lowercase hex frame".into());
        }
        let mut bytes = Vec::with_capacity(payload.len() / 2);
        for pair in payload.as_bytes().chunks_exact(2) {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
        }
        frames.push((id.to_owned(), decode(&bytes)?));
    }
    let mut output = String::new();
    for (id, frame) in frames {
        output.push_str(&id);
        output.push('\t');
        output.push_str(&execute(frame));
        output.push('\n');
    }
    print!("{output}");
    Ok(())
}
fn main() {
    if let Err(message) = run() {
        eprintln!("input rejected: {message}");
        std::process::exit(2);
    }
}
