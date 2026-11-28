//! The parsed-field updates and unconsumed suffix of node #115's RFC 2822 reader.

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ParseError {
    OutOfRange,
    Impossible,
    Invalid,
    TooShort,
}

/// Calendar fields before conversion to an instant. Weekdays start at Monday (0).
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct ParsedFields {
    pub year: Option<i32>,
    pub month: Option<u8>,
    pub day: Option<u8>,
    pub weekday: Option<u8>,
    pub hour_div_12: Option<u8>,
    pub hour_mod_12: Option<u8>,
    pub minute: Option<u8>,
    pub second: Option<u8>,
    pub offset_seconds: Option<i32>,
}

fn put<T: Copy + PartialEq>(field: &mut Option<T>, value: T) -> Result<(), ParseError> {
    match *field {
        Some(existing) if existing != value => Err(ParseError::Impossible),
        _ => {
            *field = Some(value);
            Ok(())
        }
    }
}

struct Cursor<'a>(&'a str);

impl Cursor<'_> {
    fn whitespace(&mut self) -> Result<(), ParseError> {
        let rest = self.0.trim_start();
        if self.0.is_empty() {
            return Err(ParseError::TooShort);
        }
        if rest.len() == self.0.len() {
            return Err(ParseError::Invalid);
        }
        self.0 = rest;
        Ok(())
    }

    fn number(&mut self, min: usize, max: usize) -> Result<(i64, usize), ParseError> {
        if self.0.len() < min {
            return Err(ParseError::TooShort);
        }
        let digits = self
            .0
            .bytes()
            .take(max)
            .take_while(u8::is_ascii_digit)
            .count();
        if digits < min {
            return Err(ParseError::Invalid);
        }
        let value = self.0[..digits]
            .parse()
            .map_err(|_| ParseError::OutOfRange)?;
        self.0 = &self.0[digits..];
        Ok((value, digits))
    }

    fn byte(&mut self, token: char) -> Result<(), ParseError> {
        if self.0.is_empty() {
            return Err(ParseError::TooShort);
        }
        self.0 = self.0.strip_prefix(token).ok_or(ParseError::Invalid)?;
        Ok(())
    }

    fn name(&mut self, names: &[&str]) -> Result<u8, ParseError> {
        if self.0.len() < 3 {
            return Err(ParseError::TooShort);
        }
        let key = self.0.get(..3).ok_or(ParseError::Invalid)?;
        let index = names
            .iter()
            .position(|name| key.eq_ignore_ascii_case(name))
            .ok_or(ParseError::Invalid)?;
        self.0 = &self.0[3..];
        Ok(index as u8)
    }

    fn zone(&mut self) -> Result<i32, ParseError> {
        let n = self.0.bytes().take_while(u8::is_ascii_alphabetic).count();
        if n > 0 {
            let (name, rest) = self.0.split_at(n);
            let hours = match name.as_bytes() {
                [c] if !c.eq_ignore_ascii_case(&b'J') => 0,
                _ => [
                    ("UT", 0),
                    ("GMT", 0),
                    ("EST", -5),
                    ("EDT", -4),
                    ("CST", -6),
                    ("CDT", -5),
                    ("MST", -7),
                    ("MDT", -6),
                    ("PST", -8),
                    ("PDT", -7),
                ]
                .into_iter()
                .find(|(key, _)| name.eq_ignore_ascii_case(key))
                .map(|(_, offset)| offset)
                .ok_or(ParseError::Invalid)?,
            };
            self.0 = rest;
            return Ok(hours * 3600);
        }
        let sign = match self.0.as_bytes().first() {
            Some(b'+') => 1,
            Some(b'-') => -1,
            None => return Err(ParseError::TooShort),
            _ => return Err(ParseError::Invalid),
        };
        self.0 = &self.0[1..];
        let (hours, _) = self.number(2, 2)?;
        let (minutes, _) = self.number(2, 2)?;
        if minutes >= 60 {
            return Err(ParseError::OutOfRange);
        }
        Ok(sign * (hours as i32 * 3600 + minutes as i32 * 60))
    }
}

/// Only complete comments consume input, including the whitespace preceding them.
fn after_comment(text: &str) -> Option<&str> {
    let body = text.trim_start().strip_prefix('(')?;
    let mut depth = 1usize;
    let mut chars = body.char_indices();
    while let Some((index, value)) = chars.next() {
        match value {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&body[index + 1..]);
                }
            }
            '\\' => {
                chars.next()?;
            }
            _ => {}
        }
    }
    None
}

impl ParsedFields {
    /// Read a date prefix into this record. Earlier fields survive a later error.
    pub fn parse<'a>(&mut self, text: &'a str) -> Result<&'a str, ParseError> {
        let mut c = Cursor(text.trim_start());
        if let Ok(weekday) = c.name(&["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]) {
            c.0 =
                c.0.strip_prefix(',')
                    .ok_or(ParseError::Invalid)?
                    .trim_start();
            put(&mut self.weekday, weekday)?;
        }
        let (day, _) = c.number(1, 2)?;
        if !(1..=31).contains(&day) {
            return Err(ParseError::OutOfRange);
        }
        put(&mut self.day, day as u8)?;
        c.whitespace()?;
        let month = c.name(&[
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ])?;
        put(&mut self.month, month + 1)?;
        c.whitespace()?;
        let (year, digits) = c.number(2, usize::MAX)?;
        let year = match digits {
            2 if year < 50 => year + 2000,
            2 | 3 => year + 1900,
            _ => year,
        };
        put(
            &mut self.year,
            i32::try_from(year).map_err(|_| ParseError::OutOfRange)?,
        )?;
        c.whitespace()?;
        let (hour, _) = c.number(2, 2)?;
        if hour > 23 {
            return Err(ParseError::OutOfRange);
        }
        put(&mut self.hour_div_12, hour as u8 / 12)?;
        put(&mut self.hour_mod_12, hour as u8 % 12)?;
        c.0 = c.0.trim_start();
        c.byte(':')?;
        c.0 = c.0.trim_start();
        let (minute, _) = c.number(2, 2)?;
        if minute > 59 {
            return Err(ParseError::OutOfRange);
        }
        put(&mut self.minute, minute as u8)?;
        if let Some(rest) = c.0.trim_start().strip_prefix(':') {
            c.0 = rest;
            let (second, _) = c.number(2, 2)?;
            if second > 60 {
                return Err(ParseError::OutOfRange);
            }
            put(&mut self.second, second as u8)?;
        }
        c.whitespace()?;
        put(&mut self.offset_seconds, c.zone()?)?;
        while let Some(rest) = after_comment(c.0) {
            c.0 = rest;
        }
        Ok(c.0)
    }
}
