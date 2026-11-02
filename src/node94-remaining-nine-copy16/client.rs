extern crate node94_leaf;
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
};
struct View {
    memory: BTreeMap<u64, u8>,
    events: Vec<[u64; 3]>,
}
impl View {
    fn read(&mut self, address: u64, size: usize) -> Result<Vec<u8>, ()> {
        self.events
            .push([if size == 8 { 0 } else { 1 }, address, size as u64]);
        (0..size)
            .map(|i| {
                self.memory
                    .get(&address.wrapping_add(i as u64))
                    .copied()
                    .ok_or(())
            })
            .collect()
    }
}
impl node94_leaf::Memory for View {
    type Error = ();
    fn load_u64(&mut self, address: u64) -> Result<u64, ()> {
        Ok(u64::from_le_bytes(
            self.read(address, 8)?.try_into().unwrap(),
        ))
    }
    fn read_16(&mut self, address: u64) -> Result<[u8; 16], ()> {
        Ok(self.read(address, 16)?.try_into().unwrap())
    }
    fn write_16(&mut self, address: u64, value: [u8; 16]) -> Result<(), ()> {
        self.events.push([2, address, 16]);
        let addresses: Vec<_> = (0..16).map(|i| address.wrapping_add(i)).collect();
        if addresses.iter().any(|a| !self.memory.contains_key(a)) {
            return Err(());
        }
        for (a, b) in addresses.into_iter().zip(value) {
            self.memory.insert(a, b);
        }
        Ok(())
    }
}
fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let (obj, src, mid, q, dest, seed, mask, hole) =
        (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]);
    let mut view = View {
        memory: BTreeMap::new(),
        events: vec![],
    };
    for i in -2i64..18 {
        view.memory
            .insert(dest.wrapping_add(i as u64), (seed ^ 0xa5 ^ i as u64) as u8);
    }
    for i in -2i64..18 {
        view.memory.insert(
            q.wrapping_sub(16).wrapping_add(i as u64),
            seed.wrapping_add((37 * i) as u64) as u8,
        );
    }
    let slots = [
        (obj.wrapping_add(8), dest),
        (src.wrapping_add(16), mid),
        (mid.wrapping_add(8), q),
    ];
    for (address, value) in slots {
        for (i, b) in value.to_le_bytes().into_iter().enumerate() {
            view.memory.insert(address.wrapping_add(i as u64), b);
        }
    }
    for (flag, (address, _)) in slots.into_iter().enumerate() {
        if mask & (1 << flag) != 0 {
            for i in 0..8 {
                view.memory.remove(&address.wrapping_add(i));
            }
        }
    }
    if mask & 8 != 0 {
        view.memory.remove(&q.wrapping_sub(16).wrapping_add(hole));
    }
    if mask & 16 != 0 {
        view.memory.remove(&dest.wrapping_add(hole));
    }
    let mut out = match node94_leaf::copy_16(&mut view, obj, src) {
        Ok(r) => vec![0, r.rax, r.rdx, r.rsi],
        Err(()) => vec![1, 0, 0, 0],
    };
    out.push(view.events.len() as u64);
    for e in view.events {
        out.extend(e);
    }
    out.push(view.memory.len() as u64);
    for (a, b) in view.memory {
        out.extend([a, b as u64]);
    }
    out
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
