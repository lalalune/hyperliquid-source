extern crate node94_leaf;
use std::io::{self, BufRead};
struct View {
    x: Vec<u64>,
    events: Vec<Vec<u64>>,
    called: bool,
}
impl View {
    fn finish(self, status: u64, value: u64, tail: &[u64]) -> Vec<u64> {
        let mut out = vec![status, value];
        out.extend_from_slice(tail);
        out.push(self.events.len() as u64);
        for event in self.events {
            out.extend(event);
        }
        out
    }
}

impl node94_leaf::Read for View {
    type Error = ();
    fn load_u64(&mut self, a: u64) -> Result<u64, ()> {
        self.events.push(vec![0, a, 0]);
        assert_eq!(a, self.x[0].wrapping_add(0xb0));
        if self.x[3] == 1 {
            Err(())
        } else {
            Ok(self.x[1])
        }
    }
    fn load_u8(&mut self, a: u64) -> Result<u8, ()> {
        self.events.push(vec![1, a, 0]);
        assert_eq!(a, self.x[0].wrapping_add(0xb8));
        if self.x[3] == 2 {
            Err(())
        } else {
            Ok(self.x[2] as u8)
        }
    }
}

fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let mut view = View {
        x,
        events: vec![],
        called: false,
    };
    let base = view.x[0];
    let result = node94_leaf::gated_byte(&mut view, base);
    match result {
        Ok(value) => view.finish(0, value as u64, &[]),
        Err(()) => view.finish(1, 0, &[]),
    }
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
