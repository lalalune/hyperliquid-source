use std::{collections::BTreeMap, vec, vec::Vec};

struct View {
    bytes: BTreeMap<u64, u8>,
    events: Vec<[u64; 3]>,
}
impl View {
    fn put_initial(&mut self, a: u64, value: u64) {
        for (i, b) in value.to_le_bytes().into_iter().enumerate() {
            self.bytes.insert(a.wrapping_add(i as u64), b);
        }
    }

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

    fn read(&mut self, address: u64) -> Result<u64, ()> {
        self.events.push([0, address, 0]);
        let mut bytes = [0; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self.bytes.get(&address.wrapping_add(i as u64)).ok_or(())?;
        }
        Ok(u64::from_le_bytes(bytes))
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

impl node94_leaf::Memory for View {
    type Error = ();
    fn load_u64(&mut self, a: u64) -> Result<u64, ()> {
        self.read(a)
    }
    fn store_u64(&mut self, a: u64, v: u64) -> Result<(), ()> {
        self.write(a, v, 8)
    }
}
pub fn evaluate(w: &[u64]) -> Vec<u64> {
    let mut view = View {
        bytes: BTreeMap::new(),
        events: Vec::new(),
    };
    if w[4] & 4 == 0 {
        view.put_initial(w[2], 0xa55a5aa5ff00ff00);
    }
    if w[4] & 1 == 0 {
        view.put_initial(w[0].wrapping_add(0x1200), w[1]);
    }
    if w[4] & 2 == 0 {
        view.put_initial(w[1].wrapping_add(0x30), w[3]);
    }
    view.bytes.entry(w[2].wrapping_sub(1)).or_insert(0xa5);
    view.bytes.entry(w[2].wrapping_add(8)).or_insert(0x5a);
    let result = node94_leaf::sentinel_field_read(&mut view, w[0], w[2]);
    match result {
        Ok(r) => view.output(0, [r.rax, r.rdx, r.rsi]),
        Err(()) => view.output(1, [0, 0, 0]),
    }
}
