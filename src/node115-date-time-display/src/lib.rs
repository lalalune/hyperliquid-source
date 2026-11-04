//! Independently reconstructed successful date/time display text for node #115.
//! Fixed ASCII output has no allocator, clock or native writer callbacks.
#![no_std]

#[derive(Clone, Copy, Debug)]
pub struct Date {
    year: i32,
    month: u8,
    day: u8,
}

impl Date {
    /// Safe logical fields, not an original packed-date ABI. Rejecting an
    /// invalid field set is wrapper behavior; the native formatter relies on
    /// its input's invariants and has different raw-invalid-field paths.
    pub fn new(year: i32, ordinal: u16) -> Option<Self> {
        if !(-262143..=262142).contains(&year) || ordinal == 0 {
            return None;
        }
        let february = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            29
        } else {
            28
        };
        let months = [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut left = ordinal;
        for (i, length) in months.into_iter().enumerate() {
            if left <= length {
                return Some(Self {
                    year,
                    month: (i + 1) as u8,
                    day: left as u8,
                });
            }
            left -= length;
        }
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Time {
    seconds: u32,
    nanos: u32,
}

impl Time {
    /// The accepted safe domain is a 24-hour day plus conventional leap-second
    /// encoding at second59. Complete native time-constructor validation is
    /// not claimed. Rendering is compared only for this accepted domain.
    pub fn new(seconds: u32, nanos: u32) -> Option<Self> {
        if seconds >= 86400
            || nanos >= 2_000_000_000
            || (nanos >= 1_000_000_000 && seconds % 60 != 59)
        {
            None
        } else {
            Some(Self { seconds, nanos })
        }
    }
}

/// Longest date13 + space1 + longest time18 =32 bytes. ASCII only.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    data: [u8; 32],
    used: usize,
}

impl Output {
    fn empty() -> Self {
        Self {
            data: [0; 32],
            used: 0,
        }
    }
    fn byte(&mut self, b: u8) {
        self.data[self.used] = b;
        self.used += 1;
    }
    fn number(&mut self, mut value: u32, minimum: usize) {
        let mut digits = [0_u8; 10];
        let mut used = 0;
        loop {
            digits[used] = b'0' + (value % 10) as u8;
            used += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for _ in used..minimum {
            self.byte(b'0');
        }
        for i in (0..used).rev() {
            self.byte(digits[i]);
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.used]
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).expect("renderer emits ASCII")
    }
}

fn date_into(out: &mut Output, date: Date) {
    if !(0..=9999).contains(&date.year) {
        out.byte(if date.year < 0 { b'-' } else { b'+' });
    }
    out.number(date.year.unsigned_abs(), 4);
    out.byte(b'-');
    out.number(u32::from(date.month), 2);
    out.byte(b'-');
    out.number(u32::from(date.day), 2);
}

fn time_into(out: &mut Output, time: Time) {
    let hours = time.seconds / 3600;
    let minutes = (time.seconds / 60) % 60;
    let seconds = time.seconds % 60 + u32::from(time.nanos >= 1_000_000_000);
    let fraction = time.nanos % 1_000_000_000;
    out.number(hours, 2);
    out.byte(b':');
    out.number(minutes, 2);
    out.byte(b':');
    out.number(seconds, 2);
    if fraction != 0 {
        out.byte(b'.');
        if fraction.is_multiple_of(1_000_000) {
            out.number(fraction / 1_000_000, 3);
        } else if fraction.is_multiple_of(1_000) {
            out.number(fraction / 1_000, 6);
        } else {
            out.number(fraction, 9);
        }
    }
}

pub fn render_date(date: Date) -> Output {
    let mut out = Output::empty();
    date_into(&mut out, date);
    out
}
pub fn render_time(time: Time) -> Output {
    let mut out = Output::empty();
    time_into(&mut out, time);
    out
}
pub fn render(date: Date, time: Time) -> Output {
    let mut out = Output::empty();
    date_into(&mut out, date);
    out.byte(b' ');
    time_into(&mut out, time);
    out
}
