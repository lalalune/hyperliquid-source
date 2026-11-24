// Compile the same arithmetic as a dependency and as part of its consumer.
#[inline(never)]
pub fn increment(value: u64) -> u64 {
    value + 1
}

#[cfg(not(dependency))]
fn main() {
    use std::{hint::black_box, panic::catch_unwind};

    std::panic::set_hook(Box::new(|_| {}));
    for (unit, add) in [
        ("dependency", checked_dependency::increment as fn(u64) -> u64),
        ("root", increment),
    ] {
        let ordinary = add(black_box(u64::MAX - 1));
        let boundary = match catch_unwind(|| add(black_box(u64::MAX))) {
            Ok(n) => format!("value({n})"),
            Err(_) => "panic".to_owned(),
        };
        println!("{unit} max-1={ordinary} max={boundary}");
    }
}
