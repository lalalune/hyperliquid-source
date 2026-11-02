extern crate node94_leaf;
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
};
struct View {
    x: Vec<u64>,
    bytes: BTreeMap<u64, u8>,
    events: Vec<Vec<u64>>,
}
impl View {
    fn put(&mut self, address: u64, value: u64, width: usize) {
        for (i, b) in value.to_le_bytes().into_iter().take(width).enumerate() {
            self.bytes.insert(address.wrapping_add(i as u64), b);
        }
    }
    fn new(x: Vec<u64>, slots: &[(u64, u64, usize)], missing: u64) -> Self {
        let mut view = Self {
            x,
            bytes: BTreeMap::new(),
            events: vec![],
        };
        for &(address, value, width) in slots {
            view.put(address, value, width);
        }
        for &(address, _, width) in slots {
            for a in [address.wrapping_sub(1), address.wrapping_add(width as u64)] {
                view.bytes
                    .entry(a)
                    .or_insert(a.wrapping_mul(37).wrapping_add(0xa5) as u8);
            }
        }
        for (bit, &(address, _, width)) in slots.iter().enumerate() {
            if missing & (1 << bit) != 0 {
                for i in 0..width {
                    view.bytes.remove(&address.wrapping_add(i as u64));
                }
            }
        }
        view
    }
    fn read(&mut self, address: u64) -> Result<u64, ()> {
        self.events.push(vec![0, address, 8]);
        let mut bytes = [0; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self.bytes.get(&address.wrapping_add(i as u64)).ok_or(())?;
        }
        Ok(u64::from_le_bytes(bytes))
    }
    fn write(&mut self, address: u64, value: u64, width: usize) -> Result<(), ()> {
        self.events.push(vec![1, address, width as u64, value]);
        for i in 0..width {
            self.bytes.get(&address.wrapping_add(i as u64)).ok_or(())?;
        }
        self.put(address, value, width);
        Ok(())
    }
    fn patch(&mut self, address: u64, value: u64) {
        self.events.push(vec![3, address, 8, value]);
        self.put(address, value, 8);
    }
    fn finish(self, registers: Option<Vec<u64>>) -> Vec<u64> {
        let mut out = vec![
            u64::from(registers.is_none()),
            registers.as_ref().map_or(0, |v| v.len() as u64),
        ];
        if let Some(registers) = registers {
            out.extend(registers);
        }
        out.push(self.events.len() as u64);
        for event in self.events {
            out.push(event.len() as u64);
            out.extend(event);
        }
        out.push(self.bytes.len() as u64);
        for (address, value) in self.bytes {
            out.extend([address, u64::from(value)]);
        }
        out
    }
}

impl node94_leaf::Memory for View {
    type Error = ();
    fn load_u64(&mut self, a: u64) -> Result<u64, ()> {
        self.read(a)
    }
    fn store_u64(&mut self, a: u64, v: u64) -> Result<(), ()> {
        self.write(a, v, 8)
    }
    fn store_u8(&mut self, a: u64, v: u8) -> Result<(), ()> {
        self.write(a, u64::from(v), 1)
    }
    fn invoke(&mut self, target: u64, args: [u64; 4]) -> Result<u64, ()> {
        self.events.push([vec![2, target], args.to_vec()].concat());
        if self.x[7] & 32 != 0 {
            return Err(());
        }
        if self.x[6] != 0 {
            self.patch(self.x[0].wrapping_add(8), self.x[2]);
        }
        Ok(self.x[5])
    }
}

fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let slots = [
        (x[0].wrapping_add(8), x[1], 8),
        (x[0].wrapping_add(0x20), 0x1122334455667788, 8),
        (x[0].wrapping_add(0x28), 0x7f, 1),
        (x[1].wrapping_add(0x18), x[3], 8),
        (x[2].wrapping_add(0x18), x[4], 8),
    ];
    let (object, rsi, rdx, rcx, missing) = (x[0], x[8], x[9], x[10], x[7]);
    let mut view = View::new(x, &slots, missing);
    let result = node94_leaf::refresh(&mut view, object, rsi, rdx, rcx);
    view.finish(result.ok().map(|r| vec![r.rax, r.rdx]))
}
fn main() {
    for line in io::stdin().lock().lines() {
        let x = line
            .unwrap()
            .split(',')
            .map(|s| s.parse().unwrap())
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
