#![forbid(unsafe_code)]
#[cfg(test)]
use crate::{write_parts, ByteView, Descriptor, Request, Table};
#[cfg(not(test))]
use node94_parts_writer::{write_parts, ByteView, Descriptor, Request, Table};
use std::cell::Cell;
use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

fn number(text: &str) -> u64 { u64::from_str_radix(text, 16).unwrap() }
fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| std::format!("{b:02x}")).collect() }

enum Action { State(u64), Method(u64, u64) }
struct Step { ordinal: usize, reply: u8, actions: Vec<Action> }
fn script(text: &str) -> Vec<Step> {
    if text == "-" { return Vec::new(); }
    text.split(';').map(|entry| {
        let fields: Vec<_> = entry.split('~').collect();
        assert_eq!(fields.len(), 3);
        let actions = if fields[2] == "-" { Vec::new() } else {
            fields[2].split('/').map(|action| {
                match action.as_bytes()[0] {
                    b'S' => Action::State(number(&action[1..])),
                    b'M' => {
                        let values: Vec<_> = action[1..].split(',').map(number).collect();
                        assert_eq!(values.len(), 2);
                        Action::Method(values[0], values[1])
                    }
                    _ => panic!("unknown supplied action"),
                }
            }).collect()
        };
        Step { ordinal: fields[0].parse().unwrap(), reply: fields[1].parse().unwrap(), actions }
    }).collect()
}

#[derive(PartialEq)]
struct Event { argument: Vec<u8>, data: u64, method: u64, reply: u8, state: u64, table: u64 }
struct Observer { state: u64, count: usize, events: Vec<(usize, Event)> }
fn observe(writer: &mut Observer, tables: &[Table], request: Request<'_>, steps: &[Step]) -> u8 {
    let step = steps.iter().find(|s| s.ordinal == writer.count);
    let reply = step.map_or(0, |s| s.reply);
    let event = Event { argument: request.bytes.to_vec(), data: request.data,
                        method: request.method, reply, state: writer.state, table: request.table };
    if let Some((count, _)) = writer.events.last_mut().filter(|(_, old)| *old == event) {
        *count += 1;
    } else { writer.events.push((1, event)); }
    if let Some(step) = step {
        for action in &step.actions {
            match *action {
                Action::State(value) => writer.state = value,
                Action::Method(id, method) => {
                    tables.iter().find(|t| t.id == id).unwrap().write_method.set(method);
                }
            }
        }
    }
    writer.count += 1;
    reply
}

pub fn run_line(line: &str) -> String {
    let fields: Vec<_> = line.split('\t').collect(); assert_eq!(fields.len(), 11);
    let id = fields[0]; assert!(id.bytes().all(|b| b.is_ascii_alphanumeric()));
    let records: Vec<[u64; 3]> = if fields[6] == "-" { Vec::new() } else {
        fields[6].split(',').map(|record| {
            let words: Vec<_> = record.split(':').map(number).collect();
            assert_eq!(words.len(), 3); [words[0], words[1], words[2]]
        }).collect()
    };
    let mut buffers: Vec<(u64, Vec<u8>)> = if fields[7] == "-" { Vec::new() } else {
        fields[7].split(';').map(|view| {
            let (token, bytes) = view.split_once(':').unwrap(); (number(token), unhex(bytes))
        }).collect()
    };
    buffers.sort_by_key(|(token, _)| *token);
    assert!(buffers.windows(2).all(|w| w[0].0 != w[1].0));
    let views: Vec<_> = buffers.iter().map(|(token, bytes)| ByteView { token: *token, bytes }).collect();
    let mut tables: Vec<_> = if fields[8] == "-" { Vec::new() } else {
        fields[8].split(',').map(|table| {
            let values: Vec<_> = table.split(':').map(number).collect(); assert_eq!(values.len(), 2);
            Table { id: values[0], write_method: Cell::new(values[1]) }
        }).collect()
    };
    tables.sort_by_key(|t| t.id);
    assert!(tables.windows(2).all(|w| w[0].id != w[1].id));
    let desc = Descriptor { prefix_token: number(fields[3]), prefix_len: number(fields[4]),
                            part_count: number(fields[5]), records: &records };
    let steps = script(fields[10]);
    let mut writer = Observer { state: number(fields[9]), count: 0, events: Vec::new() };
    let status = write_parts(number(fields[1]), number(fields[2]), &desc, &views, &tables, &mut writer,
                             &mut |w, t, r| observe(w, t, r, &steps));
    let mut output = String::new();
    write!(output, "{{\"callback_count\":{},\"events\":[", writer.count).unwrap();
    for (index, (count, event)) in writer.events.iter().enumerate() {
        if index != 0 { output.push(','); }
        write!(output, "{{\"count\":{count},\"event\":{{\"argument\":\"{}\",\"data\":{},\"method\":{},\"reply\":{},\"state\":{},\"table\":{}}}}}",
               hex(&event.argument), event.data, event.method, event.reply, event.state, event.table).unwrap();
    }
    output.push_str("],\"final_methods\":[");
    for (index, table) in tables.iter().enumerate() {
        if index != 0 { output.push(','); }
        write!(output, "[{},{}]", table.id, table.write_method.get()).unwrap();
    }
    write!(output, "],\"final_state\":{},\"id\":\"{id}\",\"raw_status\":{status}}}", writer.state).unwrap();
    output
}

#[cfg(not(test))]
fn main() {
    use std::io::Write as _;
    let args: Vec<_> = std::env::args().collect(); assert_eq!(args.len(), 2);
    let input = std::fs::read_to_string(&args[1]).unwrap();
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for line in input.lines() { writeln!(output, "{}", run_line(line)).unwrap(); }
}
