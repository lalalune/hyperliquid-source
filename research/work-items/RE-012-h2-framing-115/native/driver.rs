extern crate node115_h2_framing as f;
use std::io::{self,BufRead};
fn u(x:&str)->u64{x.parse().unwrap()}
fn main(){for line in io::stdin().lock().lines(){let line=line.unwrap();let p:Vec<_>=line.split('|').collect();match p[0]{
"B"=>println!("B {}",f::adjusted_cap(u(p[1])as u8,p[2].parse().unwrap(),u(p[3])).unwrap()),
"H"=>match f::h2_limits(u(p[1])){Some((_,n))=>println!("H 1 {}",n),None=>println!("H 0 0")},
"D"=>{let h=p[10];let bytes:Vec<u8>=(0..h.len()).step_by(2).map(|i|u8::from_str_radix(&h[i..i+2],16).unwrap()).collect();
let c=f::Config{maximum:u(p[1]),field_bytes:u(p[2]),offset:u(p[3]),adjustment:p[4].parse().unwrap(),skip:if p[5]=="0"{None}else{Some(u(p[6]))},big_endian:p[7]!="0"};
let state=if p[8]=="0"{f::State::Head}else{f::State::Data(u(p[9]))};let d=f::decode(c,state,&bytes);let(t,n)=match d.state{f::State::Head=>(0,0),f::State::Data(n)=>(1,n)};
println!("D {} {} {} {} {} {} {}",d.status as u8,d.consumed,t,n,d.reserve_payload,d.reserve_header,d.frame_length);},_=>panic!("unknown input")}}}
