//! Input-only client for the real supplied-state crate. No expected-file input.
use node94_funding_worker_values::{Inputs, Outcome, Position, UserState, funding_worker};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], &'static str> {
        let end = self.offset.checked_add(count).ok_or("length overflow")?;
        let slice = self.bytes.get(self.offset..end).ok_or("truncated input")?;
        self.offset = end;
        Ok(slice)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        self.take(N)?.try_into().map_err(|_| "fixed width")
    }
    fn byte(&mut self) -> Result<u8, &'static str> {
        Ok(self.array::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn i64(&mut self) -> Result<i64, &'static str> {
        Ok(i64::from_le_bytes(self.array()?))
    }
    fn count(&mut self, width: usize) -> Result<usize, &'static str> {
        let count = self.u32()? as usize;
        if count > (self.bytes.len() - self.offset) / width {
            return Err("count exceeds frame");
        }
        Ok(count)
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn count(out: &mut Vec<u8>, len: usize) -> Result<(), &'static str> {
    out.extend_from_slice(
        &u32::try_from(len)
            .map_err(|_| "output count")?
            .to_le_bytes(),
    );
    Ok(())
}

fn state_bytes(out: &mut Vec<u8>, state: &UserState) -> Result<(), &'static str> {
    out.extend_from_slice(&state.balance.to_le_bytes());
    count(out, state.positions.len())?;
    for (asset, position) in &state.positions {
        out.extend_from_slice(&asset.to_le_bytes());
        out.extend_from_slice(&position.tag.to_le_bytes());
        out.extend_from_slice(&position.local_balance.to_le_bytes());
        out.extend_from_slice(&position.size.to_le_bytes());
        for value in position.accumulators {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    Ok(())
}

fn evaluate(payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut input = Reader::new(payload);
    let address = input.array()?;
    let bypass = input.byte()?;
    let time = input.array()?;
    let balance = input.i64()?;
    let mut members = BTreeSet::new();
    let mut previous = None;
    for _ in 0..input.count(20)? {
        let member = input.array::<20>()?;
        if previous.is_some_and(|last| last >= member) {
            return Err("membership keys not strictly ordered");
        }
        previous = Some(member);
        members.insert(member);
    }
    let mut metadata = Vec::new();
    for _ in 0..input.count(8)? {
        metadata.push(input.i64()?);
    }
    let mut rates = BTreeMap::new();
    let mut previous = None;
    for _ in 0..input.count(16)? {
        let key = input.u64()?;
        if previous.is_some_and(|last| last >= key) {
            return Err("rate keys not strictly ordered");
        }
        previous = Some(key);
        rates.insert(key, input.u64()?);
    }
    let mut positions = BTreeMap::new();
    let mut previous = None;
    for _ in 0..input.count(52)? {
        let key = input.u64()?;
        if previous.is_some_and(|last| last >= key) {
            return Err("position keys not strictly ordered");
        }
        previous = Some(key);
        positions.insert(
            key,
            Position {
                tag: input.u32()?,
                local_balance: input.i64()?,
                size: input.i64()?,
                accumulators: [input.i64()?, input.i64()?, input.i64()?],
            },
        );
    }
    if !input.finished() {
        return Err("trailing payload bytes");
    }
    let state = UserState { balance, positions };
    let inputs = Inputs {
        address,
        bypass,
        members: &members,
        time,
        metadata: &metadata,
        rates: &rates,
    };
    let mut output = Vec::new();
    match funding_worker(&inputs, &state) {
        Err(error) => {
            output.push(2);
            output.extend_from_slice(&error.asset.to_le_bytes());
            output.push(error.kind as u8);
        }
        Ok(Outcome::Excluded) => {
            output.push(0);
            state_bytes(&mut output, &state)?;
        }
        Ok(Outcome::Accepted {
            state,
            rows,
            summary,
            requests,
        }) => {
            output.push(1);
            state_bytes(&mut output, &state)?;
            count(&mut output, rows.len())?;
            for row in rows {
                output.extend_from_slice(&row.asset.to_le_bytes());
                output.extend_from_slice(&row.payment.to_le_bytes());
                output.extend_from_slice(&row.original_size.to_le_bytes());
                output.extend_from_slice(&row.raw_rate.to_le_bytes());
                output.extend_from_slice(&row.product.to_le_bytes());
                output.extend_from_slice(&row.address);
                output.extend_from_slice(&row.time);
            }
            output.extend_from_slice(&summary.sum.to_le_bytes());
            output.push(u8::from(summary.maximum.is_some()));
            if let Some(maximum) = summary.maximum {
                output.extend_from_slice(&maximum.asset.to_le_bytes());
                output.extend_from_slice(&maximum.magnitude.to_le_bytes());
                output.extend_from_slice(&maximum.address);
            }
            count(&mut output, requests.len())?;
            for request in requests {
                output.extend_from_slice(&request.asset.to_le_bytes());
                output.push(request.field as u8);
            }
        }
    }
    Ok(output)
}

fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("no arguments accepted".into());
    }
    let mut bytes = Vec::new();
    io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let mut input = Reader::new(&bytes);
    let mut identifiers = BTreeSet::new();
    let mut output = io::BufWriter::new(io::stdout().lock());
    while !input.finished() {
        let id = input.u64()?;
        if !identifiers.insert(id) {
            return Err("duplicate case ID".into());
        }
        let len = input.u32()? as usize;
        let result = evaluate(input.take(len)?)?;
        output
            .write_all(&id.to_le_bytes())
            .map_err(|e| e.to_string())?;
        let len = u32::try_from(result.len()).map_err(|_| "output frame too large")?;
        output
            .write_all(&len.to_le_bytes())
            .map_err(|e| e.to_string())?;
        output.write_all(&result).map_err(|e| e.to_string())?;
    }
    output.flush().map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
