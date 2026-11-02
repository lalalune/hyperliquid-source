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
    fn read_u8(&mut self, address: u64) -> Result<u8, ()> {
        self.events.push(vec![0, address]);
        self.bytes.get(&address).copied().ok_or(())
    }
    fn read_u64(&mut self, address: u64) -> Result<u64, ()> {
        self.events.push(vec![1, address]);
        self.peek(address)
    }
    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), ()> {
        self.events.push(vec![3, address, value]);
        if self.x[9] & 16 != 0 {
            return Err(());
        }
        self.peek(address)?;
        self.put(address, value);
        Ok(())
    }
    fn insert(&mut self, target: u64, args: [u64; 4]) -> Result<(), ()> {
        let mut event = vec![2, target];
        event.extend(args);
        self.events.push(event);
        if self.x[9] & 4 != 0 {
            return Err(());
        }
        if self.x[8] != 0 {
            let address = self.x[0].wrapping_add(40);
            let value = self.x[7];
            self.put(address, value);
        }
        Ok(())
    }
}
fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let (obj, selector, third, fourth, missing) = (x[0], x[1], x[2], x[3], x[9]);
    let counter = obj.wrapping_add(40);
    let mut m = Memory {
        bytes: BTreeMap::new(),
        events: vec![],
        x,
    };
    m.put(counter, m.x[6]);
    m.bytes.insert(third.wrapping_add(32), m.x[4] as u8);
    m.bytes.insert(fourth.wrapping_add(32), m.x[5] as u8);
    if missing & 1 != 0 {
        m.bytes.remove(&third.wrapping_add(32));
    }
    if missing & 2 != 0 {
        m.bytes.remove(&fourth.wrapping_add(32));
    }
    if missing & 8 != 0 {
        m.remove_qword(counter);
    }
    let mut out = match node94_leaf::insert_byte_counter(&mut m, obj, selector, third, fourth) {
        Ok(v) => vec![0, v],
        Err(()) => vec![1, 0],
    };
    match m.peek(counter) {
        Ok(v) => out.extend([1, v]),
        Err(()) => out.extend([0, 0]),
    };
    out.push(m.events.len() as u64);
    for event in m.events {
        out.push(event.len() as u64);
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
