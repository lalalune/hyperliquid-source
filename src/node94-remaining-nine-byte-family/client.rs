extern crate node94_leaf;
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
};
struct View {
    memory: BTreeMap<u64, u8>,
    events: Vec<u64>,
}
impl node94_leaf::Read for View {
    type Error = ();
    fn load_u8(&mut self, address: u64) -> Result<u8, ()> {
        self.events.push(address);
        self.memory.get(&address).copied().ok_or(())
    }
}
fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let offsets = if x[0] == 0 {
        [0x58, 0x68]
    } else {
        [0xd0, 0xf8]
    };
    let mut view = View {
        memory: BTreeMap::new(),
        events: vec![],
    };
    for (i, offset) in offsets.into_iter().enumerate() {
        if x[4] & (1 << i) == 0 {
            view.memory
                .insert(x[1].wrapping_add(offset), x[2 + i] as u8);
        }
    }
    let result = if x[0] == 0 {
        node94_leaf::tiny_gate(&mut view, x[1])
    } else {
        node94_leaf::fallback_gate(&mut view, x[1])
    };
    let mut out = match result {
        Ok(v) => vec![0, v],
        Err(()) => vec![1, 0],
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
