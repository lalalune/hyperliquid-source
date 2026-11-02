#[path = "lib.rs"]
mod implementation;
use implementation::{local_port, Port};
use std::io::{self, BufRead};

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let ports = [
        Port::Selector0,
        Port::Selector1,
        Port::Selector2,
        Port::Selector3,
        Port::Selector4,
        Port::Selector5,
    ];
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut fields = line.split('\t');
        let selector: usize = fields.next().unwrap().parse().unwrap();
        let index: u8 = fields.next().unwrap().parse().unwrap();
        assert!(fields.next().is_none(), "inputs only; no expected output");
        match std::panic::catch_unwind(|| local_port(ports[selector], index)) {
            Ok(port) => println!("K\t{port}"),
            Err(error) => {
                let message = error.downcast_ref::<String>().unwrap();
                if message.contains("multiply") {
                    println!("M");
                } else if message.contains("add") {
                    println!("A");
                } else {
                    panic!("unqualified panic class");
                }
            }
        }
    }
}
