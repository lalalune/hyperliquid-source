extern crate node94_leaf;
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
};
const MASK: u64 = u64::MAX;
struct Memory {
    bytes: BTreeMap<u64, u8>,
    events: Vec<Vec<u64>>,
    x: Vec<u64>,
}
impl Memory {
    fn put(&mut self, address: u64, value: u64) {
        for (i, b) in value.to_le_bytes().into_iter().enumerate() {
            self.bytes.insert(address.wrapping_add(i as u64), b);
        }
    }
    fn peek(&self, address: u64) -> Result<u64, ()> {
        let mut bytes = [0; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self.bytes.get(&address.wrapping_add(i as u64)).ok_or(())?;
        }
        Ok(u64::from_le_bytes(bytes))
    }
    fn remove_qword(&mut self, address: u64) {
        for i in 0..8 {
            self.bytes.remove(&address.wrapping_add(i));
        }
    }
}

impl node94_leaf::View for Memory {
    type Error = ();
    fn read_u64(&mut self, address: u64) -> Result<u64, ()> {
        self.events.push(vec![0, address, 0]);
        self.peek(address)
    }
    fn read_u8(&mut self, address: u64) -> Result<u8, ()> {
        self.events.push(vec![1, address, 0]);
        self.bytes.get(&address).copied().ok_or(())
    }
    fn tagged_call(&mut self, target: u64, tag: u16) -> Result<u64, ()> {
        self.events.push(vec![2, target, tag as u64]);
        if self.x[6] & 8 != 0 {
            Err(())
        } else {
            Ok(self.x[5])
        }
    }
}
fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let (obj, base, count, flag, zero, missing) = (x[0], x[1], x[2], x[3], x[4], x[6]);
    let mut m = Memory {
        bytes: BTreeMap::new(),
        events: vec![],
        x,
    };
    m.put(obj.wrapping_add(16), count);
    m.put(obj.wrapping_add(8), base);
    if count < 10001 {
        for i in 0..count {
            m.bytes.insert(
                base.wrapping_add(80 * i + 78),
                if i == zero { 0 } else { flag as u8 },
            );
        }
    }
    if missing & 1 != 0 {
        m.remove_qword(obj.wrapping_add(16));
    }
    if missing & 2 != 0 {
        m.remove_qword(obj.wrapping_add(8));
    }
    if missing & 4 != 0 {
        m.bytes.remove(&base.wrapping_add(78));
    }
    let mut out = match node94_leaf::record_flag_scan(&mut m, obj) {
        Ok(v) => vec![0, v],
        Err(()) => vec![1, 0],
    };
    out.push(m.events.len() as u64);
    for event in m.events {
        out.extend(event);
    }
    out
}

fn main() {
    for line in io::stdin().lock().lines() {
        let x = line
            .unwrap()
            .split(',')
            .map(|v| v.parse().unwrap())
            .collect();
        println!(
            "{}",
            evaluate(x)
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
}
