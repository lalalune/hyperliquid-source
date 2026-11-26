#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use core::fmt::Write;
use node115_digest_reference_handoff::ReferenceRow;

/// JSON line offered to the abci_digest_quorum writer on its normal
/// serialization path. The local history lookup takes place separately.
pub fn quorum_log_line(row: &ReferenceRow) -> String {
    let mut line = alloc::format!("{{\"height\":{},\"d\":\"0x", row.height);
    for byte in row.digest {
        write!(line, "{byte:02x}").expect("writing to a String cannot fail");
    }
    line.push_str("\"}\n");
    line
}
