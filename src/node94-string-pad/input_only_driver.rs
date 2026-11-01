#![forbid(unsafe_code)]
#[cfg(test)]
use crate::{pad_str, Context, Operation, Request, Table};
#[cfg(not(test))]
use node94_string_pad::{pad_str, Context, Operation, Request, Table};
use std::cell::Cell;
use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

fn hex_u64(text: &str) -> u64 { u64::from_str_radix(text, 16).unwrap() }
fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i+2], 16).unwrap()).collect()
}
fn hex(raw: &[u8]) -> String { raw.iter().map(|b| std::format!("{b:02x}")).collect() }

enum Action { Tail(u64), Data(u64), Table(u64), Methods(u64, u64, u64) }
struct Step { ordinal: usize, reply: u8, actions: Vec<Action> }
fn script(text: &str) -> Vec<Step> {
    if text == "-" { return Vec::new(); }
    text.split(';').map(|step| {
        let mut parts = step.split('~');
        let ordinal = parts.next().unwrap().parse().unwrap();
        let reply = parts.next().unwrap().parse().unwrap();
        let actions = parts.next().unwrap();
        assert!(parts.next().is_none());
        let actions = if actions == "-" { Vec::new() } else {
            actions.split('/').map(|action| {
                let rest = &action[1..];
                match action.as_bytes()[0] {
                    b'T' => Action::Tail(hex_u64(rest)),
                    b'D' => Action::Data(hex_u64(rest)),
                    b'B' => Action::Table(hex_u64(rest)),
                    b'M' => { let values: Vec<_> = rest.split(',').map(hex_u64).collect();
                               assert_eq!(values.len(), 3); Action::Methods(values[0], values[1], values[2]) },
                    _ => panic!("unknown action"),
                }
            }).collect()
        };
        Step { ordinal, reply, actions }
    }).collect()
}

#[derive(PartialEq)]
enum Argument { Char(u32), Str(Vec<u8>) }
#[derive(PartialEq)]
struct Event {
    argument: Argument, context_data: u64, context_table: u64, context_tailword: u64,
    data: u64, method: u64, reply: u8, table: u64,
}
struct Observer { count: usize, events: Vec<(usize, Event)> }

fn observe(writer: &mut Observer, ctx: &Context, tables: &[Table], request: Request<'_>, steps: &[Step]) -> u8 {
    let step = steps.iter().find(|s| s.ordinal == writer.count);
    let reply = step.map_or(0, |s| s.reply);
    let argument = match request.operation { Operation::Char(c) => Argument::Char(c), Operation::Str(s) => Argument::Str(s.to_vec()) };
    let event = Event { argument, context_data: ctx.data.get(), context_table: ctx.table.get(),
                        context_tailword: ctx.tailword.get(), data: request.data, method: request.method,
                        reply, table: request.table };
    if let Some((count, old)) = writer.events.last_mut().filter(|(_, old)| *old == event) {
        *count += 1;
        let _ = old;
    } else { writer.events.push((1, event)); }
    if let Some(step) = step {
        for action in &step.actions {
            match *action {
                Action::Tail(w) => ctx.tailword.set(w),
                Action::Data(d) => ctx.data.set(d),
                Action::Table(t) => ctx.table.set(t),
                Action::Methods(id, c, s) => {
                    let table = tables.iter().find(|t| t.id == id).unwrap();
                    table.char_method.set(c); table.str_method.set(s);
                },
            }
        }
    }
    writer.count += 1;
    reply
}

pub fn run_line(line: &str) -> String {
    let fields: Vec<_> = line.split('\t').collect();
    assert_eq!(fields.len(), 8);
    let id = fields[0];
    assert!(id.bytes().all(|b| b.is_ascii_alphanumeric()));
    let text_bytes = unhex(fields[1]);
    let ctx = Context { tailword: Cell::new(hex_u64(fields[2])), data: Cell::new(hex_u64(fields[3])), table: Cell::new(hex_u64(fields[4])) };
    let mut tables: Vec<_> = fields[5].split(',').map(|row| {
        let values: Vec<_> = row.split(':').map(hex_u64).collect(); assert_eq!(values.len(), 3);
        Table { id: values[0], char_method: Cell::new(values[1]), str_method: Cell::new(values[2]) }
    }).collect();
    tables.sort_by_key(|t| t.id);
    assert!(tables.windows(2).all(|w| w[0].id != w[1].id));
    let steps = script(fields[6]);
    let requested = fields[7].parse::<usize>().unwrap(); assert!(requested < 8);
    let mut storage = std::vec![0; text_bytes.len() + 8];
    let offset = (requested + 8 - (storage.as_ptr() as usize & 7)) & 7;
    storage[offset..offset+text_bytes.len()].copy_from_slice(&text_bytes);
    let text = std::str::from_utf8(&storage[offset..offset+text_bytes.len()]).unwrap();
    let alignment = text.as_ptr() as usize & 7; assert_eq!(alignment, requested);
    let mut writer = Observer { count: 0, events: Vec::new() };
    let result = pad_str(&ctx, &tables, text, &mut writer,
                              &mut |w, c, t, r| observe(w, c, t, r, &steps));
    let mut out = String::new();
    write!(out, "{{\"callback_count\":{},\"events\":[", writer.count).unwrap();
    for (index, (count, event)) in writer.events.iter().enumerate() {
        if index != 0 { out.push(','); }
        write!(out, "{{\"count\":{count},\"event\":{{\"argument\":").unwrap();
        let kind = match &event.argument {
            Argument::Char(c) => { write!(out, "{c}").unwrap(); "char" },
            Argument::Str(s) => { write!(out, "\"{}\"", hex(s)).unwrap(); "str" },
        };
        write!(out, ",\"context_data\":{},\"context_table\":{},\"context_tailword\":{},\"data\":{},\"kind\":\"{kind}\",\"method\":{},\"reply\":{},\"table\":{}}}}}",
               event.context_data, event.context_table, event.context_tailword, event.data, event.method, event.reply, event.table).unwrap();
    }
    write!(out, "],\"final_data\":{},\"final_methods\":[", ctx.data.get()).unwrap();
    for (index, t) in tables.iter().enumerate() {
        if index != 0 { out.push(','); }
        write!(out, "[{},{},{}]", t.id, t.char_method.get(), t.str_method.get()).unwrap();
    }
    write!(out, "],\"final_table\":{},\"final_tailword\":{},\"id\":\"{id}\",\"raw_status\":{result},\"text_alignment\":{alignment}}}",
           ctx.table.get(), ctx.tailword.get()).unwrap();
    out
}

#[cfg(not(test))]
fn main() {
    use std::io::Write as _;
    let args: Vec<_> = std::env::args().collect(); assert_eq!(args.len(), 2);
    let inputs = std::fs::read_to_string(&args[1]).unwrap();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in inputs.lines() { writeln!(out, "{}", run_line(line)).unwrap(); }
}
