use std::{collections::BTreeMap, vec, vec::Vec};

struct View {
    bytes: BTreeMap<u64, u8>,
    events: Vec<[u64; 3]>,
}
impl View {
    fn write(&mut self, address: u64, value: u64, size: usize) -> Result<(), ()> {
        self.events
            .push([if size == 8 { 1 } else { 2 }, address, value]);
        let addresses: Vec<_> = (0..size).map(|i| address.wrapping_add(i as u64)).collect();
        if addresses.iter().any(|a| !self.bytes.contains_key(a)) {
            return Err(());
        }
        for (address, byte) in addresses.into_iter().zip(value.to_le_bytes()) {
            self.bytes.insert(address, byte);
        }
        Ok(())
    }

    fn output(self, tag: u64, registers: [u64; 3]) -> Vec<u64> {
        let mut out = vec![
            tag,
            registers[0],
            registers[1],
            registers[2],
            self.events.len() as u64,
        ];
        for e in self.events {
            out.extend(e);
        }
        out.push(self.bytes.len() as u64);
        for (a, b) in self.bytes {
            out.extend([a, b as u64]);
        }
        out
    }
}

impl node94_leaf::Store for View {
    type Error = ();
    fn store_u64(&mut self, a: u64, v: u64) -> Result<(), ()> {
        self.write(a, v, 8)
    }
    fn store_u8(&mut self, a: u64, v: u8) -> Result<(), ()> {
        self.write(a, v as u64, 1)
    }
}
pub fn evaluate(w: &[u64]) -> Vec<u64> {
    let mut view = View {
        bytes: BTreeMap::new(),
        events: Vec::new(),
    };
    for i in -2i64..24 {
        view.bytes.insert(
            w[0].wrapping_add(i as u64),
            w[1].wrapping_add((i * 37) as u64) as u8,
        );
    }
    for bit in 0..17 {
        if w[2] & (1 << bit) != 0 {
            view.bytes.remove(&w[0].wrapping_add(bit));
        }
    }
    let result = node94_leaf::self_link_initialize(&mut view, w[0]);
    match result {
        Ok(r) => view.output(0, [r.rax, r.rdx, 0]),
        Err(()) => view.output(1, [0, 0, 0]),
    }
}
