extern crate node94_leaf;
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
};
struct View {
    bytes: BTreeMap<u64, u8>,
    events: Vec<u64>,
}
impl node94_leaf::Read for View {
    type Error = ();
    fn load_u64(&mut self, address: u64) -> Result<u64, ()> {
        self.events.push(address);
        let mut bytes = [0; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self.bytes.get(&address.wrapping_add(i as u64)).ok_or(())?;
        }
        Ok(u64::from_le_bytes(bytes))
    }
}
fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let slots = [
        (x[0].wrapping_add(0x28), x[1]),
        (x[1].wrapping_add(0x198), x[3]),
        (x[1].wrapping_add(0x190), x[2]),
    ];
    let mut view = View {
        bytes: BTreeMap::new(),
        events: vec![],
    };
    for (address, value) in slots {
        for (i, b) in value.to_le_bytes().into_iter().enumerate() {
            view.bytes.insert(address.wrapping_add(i as u64), b);
        }
    }
    for (flag, (address, _)) in slots.iter().enumerate() {
        if x[4] & (1 << flag) != 0 {
            for i in 0..8 {
                view.bytes.remove(&address.wrapping_add(i));
            }
        }
    }
    let mut out = match node94_leaf::pair_load(&mut view, x[0]) {
        Ok(p) => vec![0, p.rax, p.rdx],
        Err(()) => vec![1, 0, 0],
    };
    out.push(view.events.len() as u64);
    out.extend(view.events);
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
