use std::io::{self, BufRead};
use std::os::unix::ffi::OsStrExt;
extern crate node115_reverse_path_components as own;
fn hex(b:&[u8])->String { b.iter().map(|x|format!("{x:02x}")).collect() }
fn ours(b:&[u8])->String {
 let mut it=own::Reverse::new(b);let mut r=hex(it.remaining());
 loop {r.push('|');match it.next_back(){Some(own::Component::Root)=>r.push('6'),Some(own::Component::Current)=>r.push('7'),Some(own::Component::Parent)=>r.push('8'),Some(own::Component::Normal(x))=>{r.push_str("9:");r.push_str(&hex(x));},None=>{r.push_str("10");r.push(':');r.push_str(&hex(it.remaining()));break;}}
 r.push(':');r.push_str(&hex(it.remaining()));}
 r
}
fn reference(b:&[u8])->String {
 let mut it=std::path::Path::new(std::ffi::OsStr::from_bytes(b)).components();let mut r=hex(it.as_path().as_os_str().as_bytes());
 loop {r.push('|');match it.next_back(){Some(std::path::Component::RootDir)=>r.push('6'),Some(std::path::Component::CurDir)=>r.push('7'),Some(std::path::Component::ParentDir)=>r.push('8'),Some(std::path::Component::Normal(x))=>{r.push_str("9:");r.push_str(&hex(x.as_bytes()));},None=>{r.push_str("10");r.push(':');r.push_str(&hex(it.as_path().as_os_str().as_bytes()));break;},_=>panic!("Unix prefix outside qualified scope")}
 r.push(':');r.push_str(&hex(it.as_path().as_os_str().as_bytes()));}
 r
}
fn main(){for line in io::stdin().lock().lines(){let line=line.unwrap();let bytes:Vec<u8>=line.as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();let a=ours(&bytes);let b=reference(&bytes);println!("{}\t{}",a,b);}}
