use node115_rng_buffer_selection::{EntropyOutcome, RefillOutput, State, Step, begin};
use std::fmt::Write as _;
use std::io::{self, BufRead, Write};
fn show(s: &State) -> String {
    let mut v = format!(
        "{},{},{},{},",
        s.cursor, s.remaining, s.base_budget, s.observed_epoch
    );
    for b in s.key_state {
        write!(v, "{b:02x}").unwrap();
    }
    v
}
fn run(line: &str) -> String {
    let v: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(v.len(), 7);
    let seed = v[6].parse::<u8>().unwrap();
    let mut state = State {
        cursor: v[0].parse().unwrap(),
        remaining: v[1].parse().unwrap(),
        base_budget: v[2].parse().unwrap(),
        observed_epoch: v[3].parse().unwrap(),
        key_state: std::array::from_fn(|i| (i as u8) ^ seed),
        buffer: std::array::from_fn(|i| {
            u32::from(seed)
                .wrapping_mul(0x9e3779b1)
                .wrapping_add(i as u32)
        }),
    };
    let epoch = v[4].parse().unwrap();
    let successful = v[5] == "1";
    let output = RefillOutput {
        key_state: std::array::from_fn(|i| {
            (i as u8).wrapping_mul(3).wrapping_add(seed).wrapping_add(1)
        }),
        words: std::array::from_fn(|i| (u32::from(seed) ^ 0xa5a5a5a5).wrapping_add(i as u32)),
    };
    let mut text = String::new();
    let refill = match begin(&mut state, epoch) {
        Step::Word(word) => {
            write!(text, "word={word}").unwrap();
            None
        }
        Step::Refill(request) => Some(request),
        Step::Entropy(request) => {
            write!(text, "entropy={} ", show(request.state())).unwrap();
            let outcome = if successful {
                EntropyOutcome::Seed(std::array::from_fn(|i| (i as u8).wrapping_add(seed)))
            } else {
                EntropyOutcome::Unavailable
            };
            request.resume(outcome).ok()
        }
    };
    if let Some(request) = refill {
        write!(text, "refill={} ", show(request.state())).unwrap();
        let expected_words = output.words;
        let word = request.complete(output);
        assert_eq!(state.buffer, expected_words);
        let mut followup = state.clone();
        match begin(&mut followup, epoch) {
            Step::Word(next) => assert_eq!(next, expected_words[1]),
            _ => panic!("post-refill buffer was not consumable"),
        }
        assert_eq!(followup.cursor, 2);
        write!(text, "word={word}").unwrap();
    } else if text.starts_with("entropy=") {
        write!(text, "overflow={}", show(&state)).unwrap();
        return text;
    }
    write!(text, " final={}", show(&state)).unwrap();
    text
}
fn main() {
    let out = io::stdout();
    let mut out = io::BufWriter::new(out.lock());
    for line in io::stdin().lock().lines() {
        writeln!(out, "{}", run(&line.unwrap())).unwrap();
    }
}
