use node115_replica_response_json::{
    collector::{ObservedBundle, collect_full},
    write_response,
};
use std::io::{self, Write};

const OK: &str = r#"{"user":"0x3030303030303030303030303030303030303030","res":{"status":"ok","response":{"quantity":0.1234567890123456789012345678,"flag":true}}}"#;
const ERR: &str = r#"{"user":"0x3131313131313131313131313131313131313131","res":{"status":"err","response":"fixture rejection"}}"#;

fn main() -> io::Result<()> {
    let prefix = collect_full([
        ObservedBundle::Row {
            ordinal: 4,
            reference: [0xcc; 32],
            entries: vec![OK, ERR],
        },
        ObservedBundle::Row {
            ordinal: 7,
            reference: [0xbb; 32],
            entries: vec![],
        },
        ObservedBundle::End,
        ObservedBundle::Row {
            ordinal: 11,
            reference: [0xaa; 32],
            entries: vec![OK],
        },
    ]);
    let mut out = io::stdout().lock();
    let ordinals = prefix.ordinals();
    let stop = prefix.stop_position().expect("fixture has explicit stop");
    write!(
        out,
        r#"{{"height":43,"ordinals":{ordinals:?},"stop_position":{stop},"resps":"#
    )?;
    write_response(&mut out, prefix.response(), |out, entry| {
        out.write_all(entry.as_bytes())
    })?;
    writeln!(out, "}}")
}
