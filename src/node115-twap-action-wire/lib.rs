//! Selected successful MessagePack composition for TWAP order/cancel actions.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{string::String, vec::Vec};
use core::fmt::Write;
use node115_quantity_preparation_adapter::prepare_quantity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Array,
    Map,
}
#[derive(Clone, Copy, Debug)]
pub struct Trigger<'a> {
    pub p: &'a str,
    pub a: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Details<'a> {
    pub t: Option<Trigger<'a>>,
    pub s: Option<&'a str>,
}
#[derive(Clone, Copy, Debug)]
pub struct Order<'a> {
    pub asset: u32,
    pub b: bool,
    pub quantity: u64,
    pub r: bool,
    pub m: u64,
    pub t: bool,
    pub details: Option<Details<'a>>,
}
#[derive(Clone, Copy, Debug)]
pub struct Cancel {
    pub asset: u32,
    pub t: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    QuantityDomain,
    StringTooLong,
}

fn header(out: &mut Vec<u8>, mode: Mode, fields: u8) {
    out.push((if mode == Mode::Map { 0x80 } else { 0x90 }) | fields);
}
fn key(out: &mut Vec<u8>, mode: Mode, s: &str) -> Result<(), Error> {
    if mode == Mode::Map {
        string(out, s)?;
    }
    Ok(())
}
fn string(out: &mut Vec<u8>, s: &str) -> Result<(), Error> {
    let n = u32::try_from(s.len()).map_err(|_| Error::StringTooLong)?;
    if n < 32 {
        out.push(0xa0 | n as u8)
    } else if n < 256 {
        out.extend_from_slice(&[0xd9, n as u8])
    } else if n < 65536 {
        out.push(0xda);
        out.extend_from_slice(&(n as u16).to_be_bytes())
    } else {
        out.push(0xdb);
        out.extend_from_slice(&n.to_be_bytes())
    }
    out.extend_from_slice(s.as_bytes());
    Ok(())
}
fn uint(out: &mut Vec<u8>, n: u64) {
    if n < 128 {
        out.push(n as u8)
    } else if n < 256 {
        out.extend_from_slice(&[0xcc, n as u8])
    } else if n < 65536 {
        out.push(0xcd);
        out.extend_from_slice(&(n as u16).to_be_bytes())
    } else if n <= u32::MAX as u64 {
        out.push(0xce);
        out.extend_from_slice(&(n as u32).to_be_bytes())
    } else {
        out.push(0xcf);
        out.extend_from_slice(&n.to_be_bytes())
    }
}
fn boolean(out: &mut Vec<u8>, b: bool) {
    out.push(if b { 0xc3 } else { 0xc2 })
}
fn quantity(raw: u64) -> Result<String, Error> {
    let v = prepare_quantity(raw).map_err(|_| Error::QuantityDomain)?;
    let mut digits = String::new();
    write!(&mut digits, "{}", v.coefficient).expect("String write");
    let scale = usize::from(v.scale);
    if scale == 0 {
        return Ok(digits);
    }
    if digits.len() <= scale {
        let mut result = String::from("0.");
        for _ in 0..scale - digits.len() {
            result.push('0')
        }
        result.push_str(&digits);
        Ok(result)
    } else {
        digits.insert(digits.len() - scale, '.');
        Ok(digits)
    }
}
fn action_type(out: &mut Vec<u8>, mode: Mode, name: &str) -> Result<(), Error> {
    key(out, mode, "type")?;
    string(out, name)
}
/// Encode a complete selected cancel action on normal successful writer paths.
pub fn cancel(v: Cancel, mode: Mode) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    header(&mut out, mode, 3);
    action_type(&mut out, mode, "twapCancel")?;
    key(&mut out, mode, "a")?;
    uint(&mut out, u64::from(v.asset));
    key(&mut out, mode, "t")?;
    uint(&mut out, v.t);
    Ok(out)
}
/// Encode the selected order action, including both optional details fields.
pub fn order(v: Order<'_>, mode: Mode) -> Result<Vec<u8>, Error> {
    let size = quantity(v.quantity)?;
    let mut out = Vec::new();
    header(&mut out, mode, if v.details.is_some() { 3 } else { 2 });
    action_type(&mut out, mode, "twapOrder")?;
    key(&mut out, mode, "twap")?;
    header(&mut out, mode, 6);
    key(&mut out, mode, "a")?;
    uint(&mut out, u64::from(v.asset));
    key(&mut out, mode, "b")?;
    boolean(&mut out, v.b);
    key(&mut out, mode, "s")?;
    string(&mut out, &size)?;
    key(&mut out, mode, "r")?;
    boolean(&mut out, v.r);
    key(&mut out, mode, "m")?;
    uint(&mut out, v.m);
    key(&mut out, mode, "t")?;
    boolean(&mut out, v.t);
    if let Some(d) = v.details {
        key(&mut out, mode, "details")?;
        header(&mut out, mode, 2);
        key(&mut out, mode, "t")?;
        if let Some(t) = d.t {
            header(&mut out, mode, 2);
            key(&mut out, mode, "p")?;
            string(&mut out, t.p)?;
            key(&mut out, mode, "a")?;
            boolean(&mut out, t.a);
        } else {
            out.push(0xc0)
        }
        key(&mut out, mode, "s")?;
        if let Some(s) = d.s {
            string(&mut out, s)?
        } else {
            out.push(0xc0)
        }
    }
    Ok(out)
}
