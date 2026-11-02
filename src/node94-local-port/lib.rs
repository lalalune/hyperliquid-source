//! Node #94 local-validator port arithmetic; not a networking implementation.
//!
//! The six selectors and u8 index domain are qualified by the target evidence.
//! The two overflow classes are exposed through distinguishable Rust panics;
//! this does not reproduce the captured panic runtime or original enum ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Port {
    Selector0,
    Selector1,
    Selector2,
    Selector3,
    Selector4,
    Selector5,
}

impl Port {
    pub const fn base(self) -> u16 {
        match self {
            Self::Selector0 => 4001,
            Self::Selector1 => 4002,
            Self::Selector2 => 4003,
            Self::Selector3 => 4004,
            Self::Selector4 => 3998,
            Self::Selector5 => 3999,
        }
    }
}

/// Returns the local-validator port, panicking first on multiplication overflow
/// and then on addition overflow. No OS, endpoint, connection or allocation.
pub fn local_port(port: Port, index: u8) -> u16 {
    let offset = u16::from(index)
        .checked_mul(1000)
        .expect("node94 port multiply overflow");
    port.base()
        .checked_add(offset)
        .expect("node94 port add overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ports_at_success_and_both_overflow_boundaries() {
        for port in [
            Port::Selector0,
            Port::Selector1,
            Port::Selector2,
            Port::Selector3,
            Port::Selector4,
            Port::Selector5,
        ] {
            assert_eq!(local_port(port, 0), port.base());
            assert_eq!(local_port(port, 61), port.base() + 61000);
            for index in [62, 65] {
                let panic = std::panic::catch_unwind(|| local_port(port, index)).unwrap_err();
                assert!(panic.downcast_ref::<String>().unwrap().contains("add"));
            }
            for index in [66, 255] {
                let panic = std::panic::catch_unwind(|| local_port(port, index)).unwrap_err();
                assert!(panic.downcast_ref::<String>().unwrap().contains("multiply"));
            }
        }
    }
}
