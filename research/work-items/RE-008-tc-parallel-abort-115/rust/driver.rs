//! Input-only client: expected outputs are not arguments, files or dependencies.
#![forbid(unsafe_code)]
use node115_tc_parallel_abort as m;
use std::io::{self, BufRead, Write};

fn hex(x: &[u8]) -> String { x.iter().map(|b| format!("{b:02x}")).collect() }
fn bytes(x: &str) -> Result<Vec<u8>, String> {
    if x.len() % 2 != 0 || !x.bytes().all(|c| c.is_ascii_hexdigit()) { return Err("hex".into()); }
    (0..x.len()).step_by(2).map(|i| u8::from_str_radix(&x[i..i+2],16).map_err(|_|"hex".into())).collect()
}
fn array<const N: usize>(x: &str) -> Result<[u8;N],String> { bytes(x)?.try_into().map_err(|_|"width".into()) }
fn number(x: &str) -> Result<u64,String> {
    if x.is_empty() || !x.bytes().all(|b| b.is_ascii_digit()) { return Err("number".into()); }
    x.parse().map_err(|_|"u64".into())
}
fn byte(x: &str) -> Result<u8,String> { number(x)?.try_into().map_err(|_|"u8".into()) }
fn drops(x: &[m::DropRequest]) -> String {
    if x.is_empty() { "-".into() }
    else { x.iter().map(|(p,n,a)|format!("{p}:{n}:{a}")).collect::<Vec<_>>().join(",") }
}
fn solve(line: &str) -> Result<String,String> {
    let p: Vec<_> = line.split('\t').collect();
    match (p[0],p.len()) {
        ("M",4) => {
            let r=m::merge(array(p[1])?,array(p[2])?,array(p[3])?);
            Ok(format!("{}\t{}\t{}\t{}",hex(&r.output),r.selection,drops(&r.cleanup),r.trace))
        }
        ("F",6) => {
            let rows:Vec<m::Record>=if p[4]=="-" {Vec::new()}
                else {p[4].split(',').map(array).collect::<Result<_,_>>()?};
            let after=if p[5]=="-" {Vec::new()} else {bytes(p[5])?};
            let r=m::fold(array(p[1])?,number(p[2])?,number(p[3])?,&rows,&after).ok_or("fold admission")?;
            Ok(format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",hex(&r.folder),r.consumed,r.reads,r.writes,r.reason,r.cursor,drops(&r.cleanup),r.trace))
        }
        ("P",10) => {
            let r=m::plan(number(p[1])?,byte(p[2])?,number(p[3])?,number(p[4])?,byte(p[5])?,
                          number(p[6])?,number(p[7])?,number(p[8])?,number(p[9])?).ok_or("stride")?;
            Ok(format!("{}\t{}\t{}\t{}\t{}\t{}\t{}",r.region,r.half,r.budget,r.right_count,r.right_start,r.local_end,u8::from(r.worker_observed)))
        }
        ("C",12) => {
            let r=m::closure(array(p[1])?,number(p[2])?,number(p[3])?,array(p[4])?,number(p[5])?,
                 number(p[6])?,number(p[7])?,number(p[8])?,byte(p[9])?,number(p[10])?,array(p[11])?);
            Ok(format!("{}\t{}\t{}\t{}",hex(&r.initialized),hex(&r.output),
                       r.call_values.iter().map(u64::to_string).collect::<Vec<_>>().join(":"),r.rax))
        }
        ("A",11) => {
            let rows:Vec<u64>=if p[6]=="-" {Vec::new()} else {p[6].split(',').map(number).collect::<Result<_,_>>()?};
            let r=m::admission(array(p[1])?,array(p[2])?,array(p[3])?,array(p[4])?,array(p[5])?,&rows,
                                number(p[7])?,number(p[8])?,byte(p[9])?,number(p[10])?);
            Ok(format!("{}\t{}\t{}\t{}",hex(&r.output),r.trace,u8::from(r.collection_cleanup),r.rax))
        }
        ("E",10) => {
            let a=p[1..].iter().map(|s|number(s)).collect::<Result<Vec<_>,_>>()?;
            Ok(m::entry(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]).iter().map(u64::to_string).collect::<Vec<_>>().join("\t"))
        }
        _ => Err("category/arity".into())
    }
}

fn main() {
    if std::env::args_os().len()!=1 { eprintln!("no arguments accepted");std::process::exit(2); }
    let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
    for (index,line) in stdin.lock().lines().enumerate() {
        match line.map_err(|_|"input".to_string()).and_then(|s|solve(&s)) {
            Ok(value) => { if writeln!(out,"{value}").is_err() {std::process::exit(3);} }
            Err(reason) => {eprintln!("line {}: {}",index+1,reason);std::process::exit(2);}
        }
    }
}
