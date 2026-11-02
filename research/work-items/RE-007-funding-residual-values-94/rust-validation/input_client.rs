//! Input-only qualification client. No fixture/expected file access.
#![forbid(unsafe_code)]
use node94_funding_residual_values::*;
use std::collections::BTreeSet;
use std::io::{Read, Write};

type Parsed<T> = Result<T, &'static str>;
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Parsed<[u8; N]> {
        let end = self.at.checked_add(N).ok_or("span")?;
        let raw = self.bytes.get(self.at..end).ok_or("truncated")?;
        self.at = end;
        raw.try_into().map_err(|_| "width")
    }
    fn byte(&mut self) -> Parsed<u8> {
        Ok(self.take::<1>()?[0])
    }
    fn u32(&mut self) -> Parsed<u32> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn u64(&mut self) -> Parsed<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn i64(&mut self) -> Parsed<i64> {
        Ok(i64::from_le_bytes(self.take()?))
    }
    fn address(&mut self) -> Parsed<Address> {
        Ok(Address(self.take()?))
    }
    fn state(&mut self) -> Parsed<State> {
        let mut state = State::default();
        for _ in 0..self.u32()? {
            let address = self.address()?;
            let mut user = User {
                cross_balance: self.i64()?,
                position_count: self.u64()?,
                ..User::default()
            };
            for _ in 0..self.u32()? {
                let asset = self.u64()?;
                let position = Position {
                    raw_mode: self.u32()?,
                    leverage: self.u32()?,
                    margin: self.i64()?,
                    size: self.i64()?,
                };
                if user.positions.insert(asset, position).is_some() {
                    return Err("duplicate position");
                }
            }
            if state.users.insert(address, user).is_some() {
                return Err("duplicate user");
            }
        }
        for _ in 0..self.u32()? {
            if !state.aru.insert(self.address()?) {
                return Err("duplicate ARU");
            }
        }
        for _ in 0..self.u32()? {
            let asset = self.u64()?;
            if state.auxiliary.insert(asset, self.i64()?).is_some() {
                return Err("duplicate auxiliary");
            }
        }
        for _ in 0..self.u32()? {
            if !state.users_with_positions.insert(self.address()?) {
                return Err("duplicate membership");
            }
        }
        Ok(state)
    }
}

enum Input {
    Apply(Vec<Summary>, State),
    Counts(u64, u64),
}
fn decode(raw: &[u8]) -> Parsed<Input> {
    let mut r = Reader { bytes: raw, at: 0 };
    if r.byte()? != 1 {
        return Err("version");
    }
    let input = match r.byte()? {
        0 => {
            let mut summaries = Vec::new();
            for _ in 0..r.u32()? {
                let address = r.address()?;
                let total = r.i64()?;
                let selection = match r.byte()? {
                    0 => None,
                    1 => Some(Selection {
                        asset: r.u64()?,
                        magnitude: r.u64()?,
                    }),
                    _ => return Err("selection"),
                };
                let mut records = Vec::new();
                for _ in 0..r.u32()? {
                    records.push(Record(r.take()?));
                }
                summaries.push(Summary {
                    address,
                    total,
                    selection,
                    records,
                });
            }
            Input::Apply(summaries, r.state()?)
        }
        1 => Input::Counts(r.u64()?, r.u64()?),
        _ => return Err("kind"),
    };
    if r.at != raw.len() {
        return Err("trailing bytes");
    }
    Ok(input)
}
fn count(out: &mut Vec<u8>, n: usize) -> Parsed<()> {
    out.extend_from_slice(&u32::try_from(n).map_err(|_| "output count")?.to_le_bytes());
    Ok(())
}
fn encode_state(out: &mut Vec<u8>, state: &State) -> Parsed<()> {
    count(out, state.users.len())?;
    for (address, user) in &state.users {
        out.extend_from_slice(&address.0);
        out.extend_from_slice(&user.cross_balance.to_le_bytes());
        out.extend_from_slice(&user.position_count.to_le_bytes());
        count(out, user.positions.len())?;
        for (asset, p) in &user.positions {
            out.extend_from_slice(&asset.to_le_bytes());
            out.extend_from_slice(&p.raw_mode.to_le_bytes());
            out.extend_from_slice(&p.leverage.to_le_bytes());
            out.extend_from_slice(&p.margin.to_le_bytes());
            out.extend_from_slice(&p.size.to_le_bytes());
        }
    }
    count(out, state.aru.len())?;
    for address in &state.aru {
        out.extend_from_slice(&address.0);
    }
    count(out, state.auxiliary.len())?;
    for (asset, value) in &state.auxiliary {
        out.extend_from_slice(&asset.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
    }
    count(out, state.users_with_positions.len())?;
    for address in &state.users_with_positions {
        out.extend_from_slice(&address.0);
    }
    Ok(())
}
fn execute(input: Input) -> Parsed<Vec<u8>> {
    let mut out = vec![1];
    match input {
        Input::Counts(n, m) => {
            out.push(1);
            out.push(u8::from(checked_counts(n, m).is_ok()));
        }
        Input::Apply(summaries, mut state) => {
            out.push(0);
            match apply_supplied_summaries(summaries, &mut state) {
                Ok(value) => {
                    out.push(0);
                    out.extend_from_slice(&value.total.to_le_bytes());
                    match value.winner {
                        None => out.push(0),
                        Some(winner) => {
                            out.push(1);
                            out.extend_from_slice(&winner.address.0);
                            out.extend_from_slice(&winner.asset.to_le_bytes());
                            out.extend_from_slice(&winner.magnitude.to_le_bytes());
                        }
                    }
                    count(&mut out, value.records.len())?;
                    for record in value.records {
                        out.extend_from_slice(&record.0);
                    }
                }
                Err(error) => out.push(match error {
                    Error::DuplicateSummary => 1,
                    Error::Span => 2,
                    Error::MissingUser => 3,
                    Error::MissingPosition => 4,
                    Error::SizeMagnitude => 5,
                }),
            }
            encode_state(&mut out, &state)?;
        }
    }
    Ok(out)
}
fn unhex(s: &str) -> Parsed<Vec<u8>> {
    if s.is_empty()
        || s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("hex");
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok(nibble(pair[0]) * 16 + nibble(pair[1]))
        })
        .collect()
}
fn run() -> Parsed<()> {
    if std::env::args_os().len() != 1 {
        return Err("arguments");
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|_| "stdin")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "UTF8")?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err("final LF");
    }
    let mut frames = Vec::new();
    let mut ids = BTreeSet::new();
    for line in text.split_terminator('\n') {
        let (id, raw) = line.split_once('\t').ok_or("tab")?;
        if id.len() != 7
            || !id.starts_with('C')
            || !id.as_bytes()[1..].iter().all(u8::is_ascii_digit)
            || !ids.insert(id)
        {
            return Err("ID");
        }
        frames.push((id, decode(&unhex(raw)?)?));
    }
    // No result is printed until every transport frame has been parsed.
    let mut output = Vec::new();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (id, input) in frames {
        output.extend_from_slice(id.as_bytes());
        output.push(b'\t');
        for byte in execute(input)? {
            output.push(HEX[usize::from(byte >> 4)]);
            output.push(HEX[usize::from(byte & 15)]);
        }
        output.push(b'\n');
    }
    std::io::stdout().write_all(&output).map_err(|_| "stdout")
}
fn main() {
    if let Err(error) = run() {
        eprintln!("input error: {error}");
        std::process::exit(2);
    }
}
