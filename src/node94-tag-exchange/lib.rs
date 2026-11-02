#![no_std]
#![forbid(unsafe_code)]
//! One atomic byte exchange and numeric register/address observations.

use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Effects {
    pub rax: u64,
    pub rcx: u64,
    /// Numeric original address; the supplied cell is not dereferenced through it.
    pub field_address: u64,
}

/// Exchange the normalized low tag byte with the supplied atomic field.
///
/// The cell represents the byte at original object+16. Exactly one SeqCst
/// read-modify-write returns the byte it replaced; concurrent exchanges may
/// change the cell again before this function returns. Numeric addresses wrap
/// and need not identify the cell's Rust address. Other-memory interactions,
/// original ABI, flags, faults, MMIO and return control are not projected.
pub fn exchange(tag_bits: u64, object: u64, cell: &AtomicU8) -> Effects {
    let value = match tag_bits as u8 {
        0 => 0,
        2 => 2,
        _ => 1,
    };
    let old = cell.swap(value, Ordering::SeqCst);
    Effects {
        rax: u64::from(old),
        rcx: 0,
        field_address: object.wrapping_add(16),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{sync::Barrier, thread};

    #[test]
    fn exchange_returns_the_replaced_full_byte() {
        let cell = AtomicU8::new(255);
        assert_eq!(exchange(0, 0, &cell).rax, 255);
        assert_eq!(exchange(2, 0, &cell).rax, 0);
        assert_eq!(exchange(255, 0, &cell).rax, 2);
        assert_eq!(cell.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ignores_high_tag_bits_and_reports_wrapped_address() {
        let cell = AtomicU8::new(128);
        assert_eq!(
            exchange(0x8000_0000_0000_0002, u64::MAX - 15, &cell),
            Effects {
                rax: 128,
                rcx: 0,
                field_address: 0,
            }
        );
        assert_eq!(cell.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_histories_are_complete_exchanges() {
        let orders = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        for _ in 0..64 {
            let cell = AtomicU8::new(129);
            let start = Barrier::new(3);
            let observed = thread::scope(|scope| {
                let handles = [0, 1, 2].map(|tag| {
                    let (cell, start) = (&cell, &start);
                    scope.spawn(move || {
                        start.wait();
                        exchange(tag, 0, cell).rax
                    })
                });
                handles.map(|handle| handle.join().unwrap())
            });
            let final_byte = cell.load(Ordering::SeqCst);
            assert!(orders.iter().any(|order| {
                let mut state = 129;
                let mut previous = [0_u64; 3];
                for &index in order {
                    previous[index] = u64::from(state);
                    state = index as u8;
                }
                previous == observed && state == final_byte
            }));
        }
    }
}
