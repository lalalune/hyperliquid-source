//! Node #115 slab unlink for one 0x110-byte book-order element.
//!
//! The contract is the pair of FDE bodies at `0x58dfbc0` and `0x58dff20`
//! in Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//! Event size, frame size, and the grow/unwind callees differ between
//! the twins; the element and level updates below do not.
//!
//! A nonzero element byte at `+0xd8` is a boundary: the native body calls
//! `0x4de02d0` and this model stops before that callee's writes. Bytes of
//! an event record other than the fields in [`EventFields`] are not
//! stored by the native body. This is not a whole-book match or a
//! component-completion claim.

#![no_std]
#![forbid(unsafe_code)]

pub const ELEMENT_STRIDE: usize = 0x110;
pub const VACANT_TAG: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventFields {
    pub discriminant: u64,
    pub kind: u64,
    pub field_b0: u64,
    pub argument: u64,
    pub field_f0: u64,
    pub field_f8: [u8; 16],
    pub field_108: u32,
    pub field_d2: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideCall {
    pub field_f0: u64,
    pub field_dc: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    NegativeField,
    SideCall(SideCall),
    LinkAbsent,
    Returned { output: [u8; ELEMENT_STRIDE + 1] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Continued {
    pub event: EventFields,
    pub underflow_helper: bool,
    pub end: End,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlinkStop {
    Vacant,
    EventFull,
    Continued(Continued),
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(raw)
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(raw)
}

fn saturating_dec(value: u64) -> u64 {
    value.saturating_sub(1)
}

fn link_absent(elements: &[[u8; ELEMENT_STRIDE]], length: u64, link_index: u64) -> bool {
    link_index >= length || read_u32(&elements[link_index as usize], 0) == VACANT_TAG as u32
}

/// Remove `index` from a dense slab whose length is `elements.len()`.
///
/// `counter` and `head` are the slab qwords at `+0x18` and `+0x20`.
/// `quantity` is the u64 behind the native `r9` argument. `level` is
/// the stack argument; `None` is the null pointer. `event_len` and
/// `event_cap` are the event collection's length and capacity. A full
/// collection returns [`UnlinkStop::EventFull`] after the free-list
/// update and does not simulate the native grow callee.
pub fn unlink(
    elements: &mut [[u8; ELEMENT_STRIDE]],
    counter: &mut u64,
    head: &mut u64,
    index: u64,
    argument: u64,
    quantity: &mut u64,
    level: Option<&mut [u8]>,
    event_len: u64,
    event_cap: u64,
) -> UnlinkStop {
    let length = elements.len() as u64;
    if index >= length || read_u64(&elements[index as usize], 0) == VACANT_TAG {
        return UnlinkStop::Vacant;
    }
    let saved = elements[index as usize];
    write_u64(&mut elements[index as usize], 0, VACANT_TAG);
    write_u64(&mut elements[index as usize], 8, *head);
    *counter = saturating_dec(*counter);
    *head = index;
    if event_len == event_cap {
        return UnlinkStop::EventFull;
    }
    let mut field_f8 = [0u8; 16];
    field_f8.copy_from_slice(&saved[0xf8..0x108]);
    let amount = read_u64(&saved, 0xe0);
    let underflow_helper = *quantity < amount;
    *quantity = quantity.saturating_sub(amount);
    let event = EventFields {
        discriminant: 2,
        kind: 3,
        field_b0: read_u64(&saved, 0xb0),
        argument,
        field_f0: read_u64(&saved, 0xf0),
        field_f8,
        field_108: read_u32(&saved, 0x108),
        field_d2: saved[0xd2],
    };
    let Some(level) = level else {
        let mut output = [0u8; ELEMENT_STRIDE + 1];
        output[..ELEMENT_STRIDE].copy_from_slice(&saved);
        return UnlinkStop::Continued(Continued {
            event,
            underflow_helper,
            end: End::Returned { output },
        });
    };
    if read_u64(&saved, 0xb0) >> 63 != 0 {
        return UnlinkStop::Continued(Continued {
            event,
            underflow_helper,
            end: End::NegativeField,
        });
    }
    if read_u32(level, 0x20) == 1 && read_u64(level, 0x28) == index {
        level[0x20..0x30].copy_from_slice(&saved[0x10..0x20]);
    }
    if saved[0xd8] != 0 {
        return UnlinkStop::Continued(Continued {
            event,
            underflow_helper,
            end: End::SideCall(SideCall {
                field_f0: read_u64(&saved, 0xf0),
                field_dc: read_u32(&saved, 0xdc),
            }),
        });
    }
    write_u64(level, 0x70, read_u64(level, 0x70).saturating_sub(amount));
    write_u64(level, 0x78, saturating_dec(read_u64(level, 0x78)));
    let link_a = read_u64(&saved, 8);
    let link_word = read_u64(&saved, 0x10);
    let link_b = read_u64(&saved, 0x18);
    let tag = read_u64(&saved, 0);
    if tag & 1 != 0 {
        if link_absent(elements, length, link_a) {
            return UnlinkStop::Continued(Continued {
                event,
                underflow_helper,
                end: End::LinkAbsent,
            });
        }
        write_u64(&mut elements[link_a as usize], 0x10, link_word);
        write_u64(&mut elements[link_a as usize], 0x18, link_b);
        if link_word != 0 {
            if link_absent(elements, length, link_b) {
                return UnlinkStop::Continued(Continued {
                    event,
                    underflow_helper,
                    end: End::LinkAbsent,
                });
            }
            write_u64(&mut elements[link_b as usize], 0, tag);
            write_u64(&mut elements[link_b as usize], 8, link_a);
        } else {
            write_u64(level, 0x10, tag);
            write_u64(level, 0x18, link_a);
        }
    } else {
        write_u64(level, 0, link_word);
        write_u64(level, 8, link_b);
        if link_word != 0 {
            if link_absent(elements, length, link_b) {
                return UnlinkStop::Continued(Continued {
                    event,
                    underflow_helper,
                    end: End::LinkAbsent,
                });
            }
            write_u64(&mut elements[link_b as usize], 0, tag);
            write_u64(&mut elements[link_b as usize], 8, link_a);
        } else {
            write_u64(level, 0x10, tag);
            write_u64(level, 0x18, link_a);
        }
    }
    let flag = if level[0] != 0 { 0 } else { level[0x10] ^ 1 };
    let mut output = [0u8; ELEMENT_STRIDE + 1];
    output[..ELEMENT_STRIDE].copy_from_slice(&saved);
    output[ELEMENT_STRIDE] = flag;
    UnlinkStop::Continued(Continued {
        event,
        underflow_helper,
        end: End::Returned { output },
    })
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn element(tag: u64, link_a: u64, link_word: u64, link_b: u64) -> [u8; ELEMENT_STRIDE] {
        let mut raw = [0u8; ELEMENT_STRIDE];
        raw[..8].copy_from_slice(&tag.to_le_bytes());
        raw[8..16].copy_from_slice(&link_a.to_le_bytes());
        raw[0x10..0x18].copy_from_slice(&link_word.to_le_bytes());
        raw[0x18..0x20].copy_from_slice(&link_b.to_le_bytes());
        raw[0xb0] = 4;
        raw[0xd2] = 7;
        raw[0xe0] = 9;
        raw[0xf0] = 3;
        raw[0xf8] = 0x11;
        raw[0x108] = 0x22;
        raw
    }

    #[test]
    fn vacant_and_out_of_range_do_not_mutate() {
        let mut elements = vec![element(2, 0, 0, 0), element(1, 0, 0, 0)];
        let original = elements.clone();
        let mut counter = 5u64;
        let mut head = 1u64;
        let mut quantity = 20u64;
        assert_eq!(
            unlink(
                &mut elements,
                &mut counter,
                &mut head,
                0,
                8,
                &mut quantity,
                None,
                0,
                4
            ),
            UnlinkStop::Vacant
        );
        assert_eq!(
            unlink(
                &mut elements,
                &mut counter,
                &mut head,
                2,
                8,
                &mut quantity,
                None,
                0,
                4
            ),
            UnlinkStop::Vacant
        );
        assert_eq!(elements, original);
        assert_eq!((counter, head, quantity), (5, 1, 20));
    }

    #[test]
    fn null_level_pushes_the_free_list_and_subtracts() {
        let mut elements = vec![element(4, 0, 0, 0)];
        elements[0][0xe0] = 3;
        let mut counter = 0u64;
        let mut head = 7u64;
        let mut quantity = 3u64;
        let stop = unlink(
            &mut elements,
            &mut counter,
            &mut head,
            0,
            0x55,
            &mut quantity,
            None,
            1,
            4,
        );
        assert_eq!(read_u64(&elements[0], 0), VACANT_TAG);
        assert_eq!(read_u64(&elements[0], 8), 7);
        assert_eq!((counter, head, quantity), (0, 0, 0));
        match stop {
            UnlinkStop::Continued(continued) => {
                assert!(!continued.underflow_helper);
                assert_eq!(continued.event.argument, 0x55);
                assert_eq!(continued.event.discriminant, 2);
                assert_eq!(continued.event.kind, 3);
                assert_eq!(continued.event.field_d2, 7);
                match continued.end {
                    End::Returned { output } => {
                        assert_eq!(output[ELEMENT_STRIDE], 0);
                        assert_eq!(output[0], 4);
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn underflow_records_the_helper_and_stores_zero() {
        let mut elements = vec![element(4, 0, 0, 0)];
        let mut counter = 4u64;
        let mut head = 1u64;
        let mut quantity = 2u64;
        let stop = unlink(
            &mut elements,
            &mut counter,
            &mut head,
            0,
            0,
            &mut quantity,
            None,
            0,
            1,
        );
        assert_eq!(quantity, 0);
        match stop {
            UnlinkStop::Continued(continued) => assert!(continued.underflow_helper),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn full_event_stops_after_the_free_list() {
        let mut elements = vec![element(4, 0, 0, 0)];
        let mut counter = 2u64;
        let mut head = 5u64;
        let mut quantity = 40u64;
        assert_eq!(
            unlink(
                &mut elements,
                &mut counter,
                &mut head,
                0,
                0,
                &mut quantity,
                None,
                3,
                3
            ),
            UnlinkStop::EventFull
        );
        assert_eq!(read_u64(&elements[0], 0), VACANT_TAG);
        assert_eq!(quantity, 40);
    }

    #[test]
    fn negative_field_panics_only_with_a_level() {
        let mut elements = vec![element(4, 0, 0, 0)];
        elements[0][0xb7] = 0x80;
        let mut counter = 1u64;
        let mut head = 0u64;
        let mut quantity = 20u64;
        let mut level = [0u8; 0x80];
        let stop = unlink(
            &mut elements,
            &mut counter,
            &mut head,
            0,
            0,
            &mut quantity,
            Some(&mut level),
            0,
            2,
        );
        match stop {
            UnlinkStop::Continued(continued) => {
                assert_eq!(continued.end, End::NegativeField);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(read_u64(&level, 0x70), 0);
    }

    #[test]
    fn even_zero_link_updates_both_level_pairs_and_the_flag() {
        let mut elements = vec![element(0x10, 2, 0, 6), element(4, 0, 0, 0)];
        let mut counter = 2u64;
        let mut head = 9u64;
        let mut quantity = 30u64;
        let mut level = [0u8; 0x80];
        level[0x70] = 12;
        level[0x78] = 1;
        let stop = unlink(
            &mut elements,
            &mut counter,
            &mut head,
            0,
            0,
            &mut quantity,
            Some(&mut level),
            0,
            1,
        );
        assert_eq!(read_u64(&level, 0), 0);
        assert_eq!(read_u64(&level, 8), 6);
        assert_eq!(read_u64(&level, 0x10), 0x10);
        assert_eq!(read_u64(&level, 0x18), 2);
        assert_eq!(read_u64(&level, 0x70), 3);
        assert_eq!(read_u64(&level, 0x78), 0);
        match stop {
            UnlinkStop::Continued(continued) => match continued.end {
                End::Returned { output } => assert_eq!(output[ELEMENT_STRIDE], 0x10 ^ 1),
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn odd_link_rewrites_the_neighbor_and_rejects_a_vacant_slot() {
        let mut elements = vec![
            element(1, 1, 5, 1),
            element(4, 0, 0, 0),
            element(2, 0, 0, 0),
        ];
        let mut counter = 3u64;
        let mut head = 0u64;
        let mut quantity = 40u64;
        let mut level = [1u8; 0x80];
        let stop = unlink(
            &mut elements,
            &mut counter,
            &mut head,
            0,
            0,
            &mut quantity,
            Some(&mut level),
            0,
            1,
        );
        assert_eq!(read_u64(&elements[1], 0x10), 5);
        assert_eq!(read_u64(&elements[1], 0x18), 1);
        assert_eq!(read_u64(&elements[1], 0), 1);
        assert_eq!(read_u64(&elements[1], 8), 1);
        match stop {
            UnlinkStop::Continued(continued) => match continued.end {
                End::Returned { output } => assert_eq!(output[ELEMENT_STRIDE], 0),
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }

        let mut elements = vec![element(1, 1, 0, 0), element(2, 0, 0, 0)];
        let mut level = [0u8; 0x80];
        let stop = unlink(
            &mut elements,
            &mut counter,
            &mut head,
            0,
            0,
            &mut quantity,
            Some(&mut level),
            0,
            1,
        );
        match stop {
            UnlinkStop::Continued(continued) => assert_eq!(continued.end, End::LinkAbsent),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn cached_head_is_replaced_before_a_side_call_boundary() {
        let mut elements = vec![element(4, 0, 0, 0)];
        elements[0][0x10] = 0x42;
        elements[0][0x18] = 0x7;
        elements[0][0xd8] = 1;
        elements[0][0xdc] = 0x63;
        let mut counter = 1u64;
        let mut head = 0u64;
        let mut quantity = 20u64;
        let mut level = [0u8; 0x80];
        level[0x20] = 1;
        let stop = unlink(
            &mut elements,
            &mut counter,
            &mut head,
            0,
            0,
            &mut quantity,
            Some(&mut level),
            0,
            1,
        );
        assert_eq!(level[0x20], 0x42);
        assert_eq!(read_u64(&level, 0x70), 0);
        match stop {
            UnlinkStop::Continued(continued) => match continued.end {
                End::SideCall(call) => {
                    assert_eq!(call.field_f0, 3);
                    assert_eq!(call.field_dc, 0x63);
                }
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
    }
}
