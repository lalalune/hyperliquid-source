//! Field emission from the node #115 fee-history success serializer at 0x22e0850.

use std::fmt::{self, Write};

#[derive(Debug, Default, PartialEq)]
pub struct FeeHistoryResult {
    pub base_fee_per_gas: Vec<u128>,
    pub gas_used_ratio: Vec<f64>,
    pub base_fee_per_blob_gas: Vec<u128>,
    pub blob_gas_used_ratio: Vec<f64>,
    pub oldest_block: u64,
    pub reward: Option<Vec<Vec<u128>>>,
}

fn array<W: Write, T>(
    out: &mut W,
    values: &[T],
    mut item: impl FnMut(&mut W, &T) -> fmt::Result,
) -> fmt::Result {
    out.write_str("[")?;
    for (i, value) in values.iter().enumerate() {
        if i != 0 {
            out.write_str(",")?;
        }
        item(out, value)?;
    }
    out.write_str("]")
}

fn quantity<W: Write>(out: &mut W, value: &u128) -> fmt::Result {
    write!(out, r#""{value:#x}""#)
}

fn ratio<W: Write>(out: &mut W, value: &f64) -> fmt::Result {
    if value.is_finite() {
        write!(out, "{value:?}")
    } else {
        out.write_str("null")
    }
}

impl fmt::Display for FeeHistoryResult {
    /// Emit the inner JSON-RPC result from already collected history values.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("{")?;
        if !self.base_fee_per_gas.is_empty() {
            out.write_str(r#""baseFeePerGas":"#)?;
            array(out, &self.base_fee_per_gas, quantity)?;
            out.write_str(",")?;
        }
        out.write_str(r#""gasUsedRatio":"#)?;
        array(out, &self.gas_used_ratio, ratio)?;
        if !self.base_fee_per_blob_gas.is_empty() {
            out.write_str(r#","baseFeePerBlobGas":"#)?;
            array(out, &self.base_fee_per_blob_gas, quantity)?;
        }
        if !self.blob_gas_used_ratio.is_empty() {
            out.write_str(r#","blobGasUsedRatio":"#)?;
            array(out, &self.blob_gas_used_ratio, ratio)?;
        }
        write!(out, r#","oldestBlock":"{:#x}""#, self.oldest_block)?;
        if let Some(rows) = &self.reward {
            out.write_str(r#","reward":"#)?;
            array(out, rows, |out, row| array(out, row, quantity))?;
        }
        out.write_str("}")
    }
}
