//! The selected compact JSON writer for ordinary native order outcomes.

use std::io::{self, Write};

use crate::{entry::quoted_text, fixed_hex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderStatus<'a> {
    Filled {
        total_size: &'a str,
        average_price: &'a str,
        order_id: u64,
        client_order_id: Option<[u8; 16]>,
    },
    Resting {
        order_id: u64,
        client_order_id: Option<[u8; 16]>,
    },
    WaitingForFill,
    WaitingForTrigger,
    Error(&'a str),
}

fn write_oid(
    out: &mut impl Write,
    order_id: u64,
    client_order_id: Option<[u8; 16]>,
) -> io::Result<()> {
    write!(out, "\"oid\":{order_id}")?;
    if let Some(cloid) = client_order_id {
        out.write_all(b",\"cloid\":")?;
        fixed_hex(out, &cloid)?;
    }
    out.write_all(b"}}")
}

/// Emit data for the order arm. Quantity strings are supplied after normalization.
pub fn write_order(out: &mut impl Write, statuses: &[OrderStatus<'_>]) -> io::Result<()> {
    out.write_all(b"{\"type\":\"order\",\"data\":{\"statuses\":[")?;
    for (index, status) in statuses.iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        match status {
            OrderStatus::Filled {
                total_size,
                average_price,
                order_id,
                client_order_id,
            } => {
                out.write_all(b"{\"filled\":{\"totalSz\":")?;
                quoted_text(out, total_size)?;
                out.write_all(b",\"avgPx\":")?;
                quoted_text(out, average_price)?;
                out.write_all(b",")?;
                write_oid(out, *order_id, *client_order_id)?;
            }
            OrderStatus::Resting {
                order_id,
                client_order_id,
            } => {
                out.write_all(b"{\"resting\":{")?;
                write_oid(out, *order_id, *client_order_id)?;
            }
            OrderStatus::WaitingForFill => out.write_all(b"\"waitingForFill\"")?,
            OrderStatus::WaitingForTrigger => out.write_all(b"\"waitingForTrigger\"")?,
            OrderStatus::Error(text) => {
                out.write_all(b"{\"error\":")?;
                quoted_text(out, text)?;
                out.write_all(b"}")?;
            }
        }
    }
    out.write_all(b"]}}")
}
