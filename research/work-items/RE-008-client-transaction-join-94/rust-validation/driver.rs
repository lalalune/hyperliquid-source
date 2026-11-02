//! Input-only client of the actual crate. No expected/corpus files are read.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::sync::Arc;

use node94_consensus_admission::client_transaction_join::{
    checked_row_bytes, join_transactions, ClientJoinInput, JoinError, JoinedTransaction,
};
use node94_consensus_admission::TransactionHash;

#[derive(Clone, Copy, Debug)]
struct InvalidView;

struct Reader<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("span overflow")?;
        let raw = self.raw.get(self.pos..end).ok_or("truncated frame")?;
        self.pos = end;
        Ok(raw)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn long(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn blob(&mut self) -> Result<&'a [u8], String> {
        let n = usize::try_from(self.word()?).map_err(|_| "blob length")?;
        self.take(n)
    }
    fn count(&mut self, minimum_width: usize) -> Result<usize, String> {
        let n = usize::try_from(self.word()?).map_err(|_| "count")?;
        if n > (self.raw.len() - self.pos) / minimum_width {
            return Err("count exceeds remaining frame".into());
        }
        Ok(n)
    }
    fn done(&self) -> Result<(), String> {
        if self.pos == self.raw.len() {
            Ok(())
        } else {
            Err("trailing frame bytes".into())
        }
    }
}

fn hash_view(raw: &[u8]) -> Result<Vec<TransactionHash>, InvalidView> {
    let n = raw.get(..8).ok_or(InvalidView)?;
    let n = usize::try_from(u64::from_le_bytes(n.try_into().unwrap())).map_err(|_| InvalidView)?;
    let end = n
        .checked_mul(32)
        .and_then(|x| x.checked_add(8))
        .ok_or(InvalidView)?;
    if end != raw.len() {
        return Err(InvalidView);
    }
    Ok(raw[8..]
        .chunks_exact(32)
        .map(|bytes| TransactionHash(bytes.try_into().unwrap()))
        .collect())
}

fn map_view(
    raw: &[u8],
    pool: &[Arc<Vec<u8>>],
) -> Result<BTreeMap<TransactionHash, Arc<Vec<u8>>>, InvalidView> {
    let n = raw.get(..8).ok_or(InvalidView)?;
    let n = usize::try_from(u64::from_le_bytes(n.try_into().unwrap())).map_err(|_| InvalidView)?;
    let end = n
        .checked_mul(36)
        .and_then(|x| x.checked_add(8))
        .ok_or(InvalidView)?;
    if end != raw.len() {
        return Err(InvalidView);
    }
    let mut map = BTreeMap::new();
    let mut previous = None;
    for row in raw[8..].chunks_exact(36) {
        let key = TransactionHash(row[..32].try_into().unwrap());
        if previous.is_some_and(|p| p >= key) {
            return Err(InvalidView);
        }
        let id = u32::from_le_bytes(row[32..].try_into().unwrap()) as usize;
        let value = pool.get(id).ok_or(InvalidView)?;
        map.insert(key, Arc::clone(value));
        previous = Some(key);
    }
    Ok(map)
}

fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let n = u32::try_from(bytes.len()).map_err(|_| "output blob length")?;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn object_id(pool: &[Arc<Vec<u8>>], value: &Arc<Vec<u8>>) -> u32 {
    // An unexpected new object still yields a complete discriminating output;
    // the sentinel cannot equal any valid fixture pool identity.
    pool.iter()
        .position(|candidate| Arc::ptr_eq(candidate, value))
        .and_then(|i| u32::try_from(i).ok())
        .unwrap_or(u32::MAX)
}

fn evaluate(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = Reader { raw, pos: 0 };
    let kind = reader.byte()?;
    if kind == 2 {
        let n = reader.long()?;
        reader.done()?;
        let mut out = vec![2];
        match checked_row_bytes(n) {
            Some(bytes) => {
                out.push(1);
                out.extend_from_slice(&(bytes as u64).to_le_bytes());
            }
            None => out.push(0),
        }
        return Ok(out);
    }
    if kind != 1 {
        return Err("unknown frame kind".into());
    }
    let block = Arc::new(reader.blob()?.to_vec());
    let weak = Arc::downgrade(&block);
    let time: [u8; 12] = reader.take(12)?.try_into().unwrap();
    let count = reader.count(4)?;
    let mut pool = Vec::new();
    for _ in 0..count {
        pool.push(Arc::new(reader.blob()?.to_vec()));
    }
    let hashes = hash_view(reader.blob()?);
    let map = map_view(reader.blob()?, &pool);
    let supplied = match reader.byte()? {
        0 => None,
        1 => {
            let count = reader.count(36)?;
            let mut rows = Vec::new();
            for _ in 0..count {
                let hash = TransactionHash(reader.take(32)?.try_into().unwrap());
                let id = reader.word()? as usize;
                let bytes = Arc::clone(pool.get(id).ok_or("supplied object ID")?);
                rows.push(JoinedTransaction { hash, bytes });
            }
            Some(Arc::new(rows))
        }
        _ => return Err("invalid supplied option".into()),
    };
    reader.done()?;
    let h_calls = Cell::new(0u8);
    let m_calls = Cell::new(0u8);
    let result = join_transactions(
        ClientJoinInput {
            block,
            rows: supplied.as_ref().map(Arc::clone),
            time,
        },
        || {
            h_calls.set(h_calls.get() + 1);
            hashes.as_ref().map(Vec::as_slice).map_err(|_| InvalidView)
        },
        || {
            m_calls.set(m_calls.get() + 1);
            map.as_ref().map_err(|_| InvalidView)
        },
    );
    let status = match &result {
        Ok(_) => 0,
        Err(JoinError::MissingTransaction(_)) => 1,
        Err(JoinError::HashView(_)) => 2,
        Err(JoinError::MapView(_)) => 3,
        Err(JoinError::RowCountLimit) => 4,
        Err(JoinError::Reservation) => 5,
    };
    let live = u8::from(weak.upgrade().is_some());
    let identity = match &result {
        Ok(value) => {
            if supplied
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, &value.rows))
            {
                1
            } else {
                2
            }
        }
        Err(_) => 0,
    };
    let outer_live = match &result {
        Ok(value) => Arc::strong_count(&value.rows),
        Err(_) => supplied.as_ref().map_or(0, Arc::strong_count),
    };
    let mut out = vec![1, status, h_calls.get(), m_calls.get(), live, identity];
    match &result {
        Ok(value) => {
            put_blob(&mut out, &value.block)?;
            out.extend_from_slice(&value.time);
            out.extend_from_slice(
                &u32::try_from(value.rows.len())
                    .map_err(|_| "row count")?
                    .to_le_bytes(),
            );
            for row in value.rows.iter() {
                out.extend_from_slice(&row.hash.0);
                out.extend_from_slice(&object_id(&pool, &row.bytes).to_le_bytes());
                put_blob(&mut out, &row.bytes)?;
            }
        }
        Err(JoinError::MissingTransaction(hash)) => out.extend_from_slice(&hash.0),
        Err(_) => {}
    }
    let live_counts = pool.iter().map(Arc::strong_count).collect::<Vec<_>>();
    drop(result);
    out.extend_from_slice(
        &u32::try_from(pool.len())
            .map_err(|_| "pool count")?
            .to_le_bytes(),
    );
    for (object, before) in pool.iter().zip(live_counts) {
        out.extend_from_slice(&(before as u64).to_le_bytes());
        out.extend_from_slice(&(Arc::strong_count(object) as u64).to_le_bytes());
    }
    out.push(u8::from(weak.upgrade().is_some()));
    out.extend_from_slice(
        &u32::try_from(outer_live)
            .map_err(|_| "outer count")?
            .to_le_bytes(),
    );
    out.extend_from_slice(&(supplied.as_ref().map_or(0, Arc::strong_count) as u32).to_le_bytes());
    out.push(u8::from(map.is_ok()));
    if let Ok(map) = &map {
        out.extend_from_slice(
            &u32::try_from(map.len())
                .map_err(|_| "map count")?
                .to_le_bytes(),
        );
        for (hash, bytes) in map {
            out.extend_from_slice(&hash.0);
            out.extend_from_slice(&object_id(&pool, bytes).to_le_bytes());
            put_blob(&mut out, bytes)?;
        }
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("noncanonical hex".into()),
    }
}

fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("arguments are not accepted".into());
    }
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())?;
    if !input.is_empty() && input.last() != Some(&b'\n') {
        return Err("missing final LF".into());
    }
    let text = std::str::from_utf8(&input).map_err(|_| "non-UTF8 input")?;
    let mut seen = BTreeSet::new();
    let mut output = String::new();
    for line in text.split_terminator('\n') {
        let (id, encoded) = line.split_once('\t').ok_or("missing field")?;
        if id.len() != 7
            || !id.starts_with('C')
            || !id.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        {
            return Err("invalid opaque ID".into());
        }
        if !seen.insert(id.to_owned()) || encoded.len() % 2 != 0 {
            return Err("duplicate ID or hex width".into());
        }
        let raw = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Ok((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
            .collect::<Result<Vec<_>, String>>()?;
        let value = evaluate(&raw)?;
        output.push_str(id);
        output.push('\t');
        for byte in value {
            use std::fmt::Write as _;
            write!(output, "{byte:02x}").map_err(|_| "output formatting")?;
        }
        output.push('\n');
    }
    io::stdout()
        .write_all(output.as_bytes())
        .map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("input client: {error}");
        std::process::exit(2);
    }
}
