#![no_std]
#![forbid(unsafe_code)]
//! One total numeric family extracted from node #94, not its record loop.

/// A newly chosen Rust result, not the original state block or native ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchLimit {
    pub quotient: u64,
    pub stop: u64,
    /// Only the original numeric stop-equality guard, not loop admission.
    pub zero_guard: bool,
}

/// Compute the raw modular distances, minimum quotient, stop and zero guard.
///
/// Array words are raw scalar values, not established pointers/capacities.
/// No table, output write, refill, input-order or progress behavior is supplied.
pub fn batch_limit_stop(input0: u64, lower: u64, outputs: [u64; 4], ends: [u64; 4]) -> BatchLimit {
    let mut quotient = input0.wrapping_sub(lower) / 7;
    for lane in 0..4 {
        let output_limit = ends[lane].wrapping_sub(outputs[lane]) / 10;
        quotient = core::cmp::min(quotient, output_limit);
    }
    // quotient <= u64::MAX / 10, so multiplying by five cannot overflow.
    // The final addition can wrap, even when the quotient is nonzero.
    let stop = outputs[3].wrapping_add(quotient * 5);
    BatchLimit { quotient, stop, zero_guard: stop == outputs[3] }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::batch_limit_stop;

    #[test]
    fn authenticated_scalar_expression_vectors() {
        let mut count = 0;
        for line in include_str!("target-vectors.tsv").lines() {
            let fields: std::vec::Vec<u64> = line.split('\t').map(|s| s.parse().unwrap()).collect();
            assert_eq!(fields.len(), 13);
            let outputs = [fields[2], fields[3], fields[4], fields[5]];
            let ends = [fields[6], fields[7], fields[8], fields[9]];
            let result = batch_limit_stop(fields[0], fields[1], outputs, ends);
            assert_eq!((result.quotient, result.stop, u64::from(result.zero_guard)),
                       (fields[10], fields[11], fields[12]), "input {:?}", &fields[..10]);
            count += 1;
        }
        assert!(count >= 512, "the target-derived corpus must be present");
    }
}
