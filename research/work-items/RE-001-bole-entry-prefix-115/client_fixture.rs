use node115_bole_entry_prefix::{prefix, Frontier, Inputs, LookupLane};
#[test]
fn sealed_native_frontiers() {
    {
        let input = Inputs {
            primary: 0,
            primary_len: 0,
            indices: &[],
            occupied: &[],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row0");
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 0,
            indices: &[2, 1, 0],
            occupied: &[1],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row101");
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 0,
            indices: &[],
            occupied: &[1, 1, 1],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row202");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 0,
            indices: &[],
            occupied: &[],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 1,
                length: 0
            }),
            "sealed row280"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 0,
            indices: &[2, 1, 0],
            occupied: &[],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 1,
                length: 0
            }),
            "sealed row303"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 0,
            indices: &[0],
            occupied: &[0, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 1,
                length: 0
            }),
            "sealed row404"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 0,
            indices: &[0, 0, 1],
            occupied: &[1, 1, 1],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 1,
                length: 0
            }),
            "sealed row505"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 0,
            indices: &[0],
            occupied: &[0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 0
            }),
            "sealed row606"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 0,
            indices: &[0, 0, 1],
            occupied: &[0, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 0
            }),
            "sealed row707"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 0,
            indices: &[1],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 0
            }),
            "sealed row808"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 0,
            indices: &[18446744073709551615],
            occupied: &[0],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 0
            }),
            "sealed row909"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 0,
            indices: &[1],
            occupied: &[1, 1, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 0
            }),
            "sealed row1010"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 0,
            indices: &[18446744073709551615],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 0
            }),
            "sealed row1111"
        );
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 1,
            indices: &[2],
            occupied: &[1],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row1212");
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 1,
            indices: &[0, 18446744073709551615],
            occupied: &[1, 1, 0],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row1313");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 1,
            indices: &[],
            occupied: &[],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 1,
                length: 1
            }),
            "sealed row1400"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 1,
            indices: &[2],
            occupied: &[],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 1,
                length: 1
            }),
            "sealed row1414"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 1,
            indices: &[0, 18446744073709551615],
            occupied: &[1],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 1,
                length: 1
            }),
            "sealed row1515"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 1,
            indices: &[0, 1, 2],
            occupied: &[1, 1, 1],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 1,
                length: 1
            }),
            "sealed row1616"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 1,
            indices: &[1, 2, 1, 0],
            occupied: &[],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 1
            }),
            "sealed row1717"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 1,
            indices: &[0, 1, 2],
            occupied: &[0, 1, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 1
            }),
            "sealed row1818"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 1,
            indices: &[1, 2, 1, 0],
            occupied: &[1, 1, 1],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 1
            }),
            "sealed row1919"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 1,
            indices: &[2, 1, 0],
            occupied: &[0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 1
            }),
            "sealed row2020"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 1,
            indices: &[],
            occupied: &[1, 1, 0],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 1
            }),
            "sealed row2121"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 1,
            indices: &[2, 1, 0],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 1
            }),
            "sealed row2222"
        );
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 2,
            indices: &[],
            occupied: &[1],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row2323");
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 2,
            indices: &[0, 0, 1],
            occupied: &[1, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row2424");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0],
            occupied: &[],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 0,
                length: 0
            }),
            "sealed row2524"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0],
            occupied: &[],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 0,
                length: 0
            }),
            "sealed row2525"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0],
            occupied: &[],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 0,
                length: 0
            }),
            "sealed row2526"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0],
            occupied: &[0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 0,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row2564"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0],
            occupied: &[0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 0,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row2567"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 0, 1],
            occupied: &[1],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 1,
                length: 1
            }),
            "sealed row2626"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[2],
            occupied: &[0, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 2,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row2652"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[2],
            occupied: &[0, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 2,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row2655"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2],
            occupied: &[0, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 0,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row2656"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0],
            occupied: &[1, 1, 1],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row2727");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[1],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 1,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row2768"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[1],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 1,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row2771"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 2,
            indices: &[18446744073709551615],
            occupied: &[],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 2
            }),
            "sealed row2828"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 2,
            indices: &[1],
            occupied: &[0, 1, 0],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 2
            }),
            "sealed row2929"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 2,
            indices: &[18446744073709551615],
            occupied: &[1, 1, 1],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 2,
                length: 2
            }),
            "sealed row3030"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 2,
            indices: &[1],
            occupied: &[0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 2
            }),
            "sealed row3131"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 2,
            indices: &[0, 18446744073709551615],
            occupied: &[0, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 2
            }),
            "sealed row3232"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 2,
            indices: &[2],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 2
            }),
            "sealed row3333"
        );
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 3,
            indices: &[0, 18446744073709551615],
            occupied: &[0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row3434");
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 3,
            indices: &[2],
            occupied: &[1, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row3535");
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 3,
            indices: &[1, 2, 1, 0],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row3636");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 3,
            indices: &[0, 1, 2],
            occupied: &[1],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 1,
                length: 1
            }),
            "sealed row3737"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 3,
            indices: &[1, 2, 1, 0],
            occupied: &[1, 1, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row3838");
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 3,
            indices: &[0, 1, 2],
            occupied: &[],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 0,
                length: 0
            }),
            "sealed row3939"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 3,
            indices: &[],
            occupied: &[0, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row4040");
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 3,
            indices: &[2, 1, 0],
            occupied: &[1, 1, 1],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row4141");
    }
    {
        let input = Inputs {
            primary: 3,
            primary_len: 3,
            indices: &[],
            occupied: &[0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 3,
                length: 3
            }),
            "sealed row4242"
        );
    }
    {
        let input = Inputs {
            primary: 3,
            primary_len: 3,
            indices: &[2, 1, 0],
            occupied: &[0, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 3,
                length: 3
            }),
            "sealed row4343"
        );
    }
    {
        let input = Inputs {
            primary: 3,
            primary_len: 3,
            indices: &[0],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 3,
                length: 3
            }),
            "sealed row4444"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 3,
            indices: &[0, 0, 1],
            occupied: &[0],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 3
            }),
            "sealed row4545"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 3,
            indices: &[0],
            occupied: &[1, 1, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 3
            }),
            "sealed row4646"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 3,
            indices: &[0, 0, 1],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 3
            }),
            "sealed row4747"
        );
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 8,
            indices: &[1],
            occupied: &[1],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row4848");
    }
    {
        let input = Inputs {
            primary: 0,
            primary_len: 8,
            indices: &[18446744073709551615],
            occupied: &[1, 1, 0],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row4949");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 8,
            indices: &[1],
            occupied: &[],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 1,
                length: 0
            }),
            "sealed row5050"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 8,
            indices: &[18446744073709551615],
            occupied: &[1],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 18446744073709551615,
                length: 1
            }),
            "sealed row5151"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 8,
            indices: &[2],
            occupied: &[1, 1, 1],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row5252");
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 8,
            indices: &[0, 18446744073709551615],
            occupied: &[],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 0,
                length: 0
            }),
            "sealed row5353"
        );
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 8,
            indices: &[2],
            occupied: &[0, 1, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row5454");
    }
    {
        let input = Inputs {
            primary: 2,
            primary_len: 8,
            indices: &[0, 18446744073709551615],
            occupied: &[1, 1, 1],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 18446744073709551615,
                length: 3
            }),
            "sealed row5555"
        );
    }
    {
        let input = Inputs {
            primary: 8,
            primary_len: 8,
            indices: &[0, 1, 2],
            occupied: &[0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 8,
                length: 8
            }),
            "sealed row5656"
        );
    }
    {
        let input = Inputs {
            primary: 8,
            primary_len: 8,
            indices: &[1, 2, 1, 0],
            occupied: &[0, 1, 0],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 8,
                length: 8
            }),
            "sealed row5757"
        );
    }
    {
        let input = Inputs {
            primary: 8,
            primary_len: 8,
            indices: &[0, 1, 2],
            occupied: &[18446744073709551615, 0, 7, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 8,
                length: 8
            }),
            "sealed row5858"
        );
    }
    {
        let input = Inputs {
            primary: 7,
            primary_len: 8,
            indices: &[1, 2, 1, 0],
            occupied: &[0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::SecondaryGuard {
                index: 1,
                length: 1
            }),
            "sealed row5959"
        );
    }
    {
        let input = Inputs {
            primary: 7,
            primary_len: 8,
            indices: &[2, 1, 0],
            occupied: &[1, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 7,
                secondary: 2,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6060"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 8,
            indices: &[],
            occupied: &[],
            header: 1,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 8
            }),
            "sealed row6161"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 8,
            indices: &[2, 1, 0],
            occupied: &[1],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 8
            }),
            "sealed row6262"
        );
    }
    {
        let input = Inputs {
            primary: 18446744073709551615,
            primary_len: 8,
            indices: &[],
            occupied: &[1, 1, 1],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::PrimaryGuard {
                index: 18446744073709551615,
                length: 8
            }),
            "sealed row6363"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0],
            occupied: &[1],
            header: 9223372036854775807,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row6464");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2],
            occupied: &[1, 0, 0],
            header: 7,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 1,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6565"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3],
            occupied: &[1, 1, 0, 0],
            header: 9223372036854775807,
            map_len: 18446744073709551615,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 2,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6666"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3],
            occupied: &[1, 1, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 3,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6676"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3],
            occupied: &[1, 1, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 3,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6689"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4],
            occupied: &[1, 1, 0, 0, 0],
            header: 7,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 2,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6767"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4],
            occupied: &[1, 1, 1, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 4,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6802"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4],
            occupied: &[1, 1, 1, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 4,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6815"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5],
            occupied: &[1, 0, 0, 0, 0, 0],
            header: 1,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 1,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6868"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5],
            occupied: &[1, 1, 1, 1, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 5,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6949"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5],
            occupied: &[1, 1, 1, 1, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 5,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6962"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5],
            occupied: &[1, 1, 1, 1, 1, 0],
            header: 18446744073709551615,
            map_len: 18446744073709551615,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 5,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row6969"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5, 6],
            occupied: &[1, 1, 1, 0, 0, 0, 0],
            header: 9223372036854775809,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 3,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row7070"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5, 6],
            occupied: &[1, 1, 1, 1, 1, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 6,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row7117"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5, 6],
            occupied: &[1, 1, 1, 1, 1, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 6,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row7130"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5, 6, 7],
            occupied: &[0, 0, 0, 0, 0, 0, 0, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row7171");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5, 6, 7],
            occupied: &[1, 1, 1, 1, 1, 0, 0, 0],
            header: 7,
            map_len: 18446744073709551615,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 5,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row7272"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5, 6, 7],
            occupied: &[1, 1, 1, 1, 1, 1, 1, 0],
            header: 0,
            map_len: 0,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::B,
                primary: 1,
                secondary: 7,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row7306"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[0, 1, 2, 3, 4, 5, 6, 7],
            occupied: &[1, 1, 1, 1, 1, 1, 1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 17,
            float_bits: 9221120237041090626,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 7,
                auxiliary: 17,
                float_bits: 9221120237041090626
            }),
            "sealed row7319"
        );
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[1, 0],
            occupied: &[1, 0],
            header: 9223372036854775808,
            map_len: 0,
            auxiliary: 1,
            float_bits: 0,
        };
        assert_eq!(prefix(input), Some(Frontier::Returned2), "sealed row7373");
    }
    {
        let input = Inputs {
            primary: 1,
            primary_len: 2,
            indices: &[1, 0],
            occupied: &[1, 0],
            header: 9223372036854775808,
            map_len: 1,
            auxiliary: 18446744073709551615,
            float_bits: 18446744073709551615,
        };
        assert_eq!(
            prefix(input),
            Some(Frontier::Lookup {
                lane: LookupLane::A,
                primary: 1,
                secondary: 1,
                auxiliary: 18446744073709551615,
                float_bits: 18446744073709551615
            }),
            "sealed row7419"
        );
    }
}
