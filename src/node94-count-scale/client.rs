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

impl node94_leaf::Context for View {
    type Error = ();
    fn load_u32(&mut self, a: u64) -> Result<u32, ()> {
        self.events.push(vec![0, a, 0]);
        assert_eq!(a, self.x[0]);
        if self.x[7] == 1 {
            Err(())
        } else {
            Ok(self.x[1] as u32)
        }
    }
    fn load_u64(&mut self, a: u64) -> Result<u64, ()> {
        self.events.push(vec![1, a, 0]);
        assert_eq!(a, self.x[0].wrapping_add(8));
        if (!self.called && self.x[7] == 2) || (self.called && self.x[7] == 4) {
            Err(())
        } else {
            Ok(if self.called { self.x[4] } else { self.x[2] })
        }
    }
    fn invoke(&mut self, target: u64, args: [u64; 4]) -> Result<u64, ()> {
        self.events.push([vec![2, target], args.to_vec()].concat());
        self.called = true;
        if self.x[7] == 3 {
            Err(())
        } else {
            Ok(self.x[3])
        }
    }
}

fn evaluate(x: Vec<u64>) -> Vec<u64> {
    let mut view = View {
        x,
        events: vec![],
        called: false,
    };
    let (state, context, rdx) = (view.x[0], view.x[5], view.x[6]);
    let result = node94_leaf::count_scale(&mut view, state, context, rdx);
    match result {
        Ok(v) => view.finish(0, v as u64, &[]),
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
