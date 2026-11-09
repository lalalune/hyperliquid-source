use node115_twap_action_wire::{Cancel, Details, Error, Mode, Order, Trigger, cancel, order};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(core::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn fixed_examples_and_quantity_domain() {
    assert_eq!(
        cancel(Cancel { asset: 1, t: 2 }, Mode::Map).unwrap(),
        b"\x83\xa4type\xaatwapCancel\xa1a\x01\xa1t\x02"
    );
    let v = Order {
        asset: 1,
        b: true,
        quantity: 123456789,
        r: false,
        m: 5,
        t: true,
        details: None,
    };
    assert_eq!(
        order(v, Mode::Array).unwrap(),
        b"\x92\xa9twapOrder\x96\x01\xc3\xaa1.23456789\xc2\x05\xc3"
    );
    assert_eq!(
        order(
            Order {
                quantity: 1 << 63,
                ..v
            },
            Mode::Map
        ),
        Err(Error::QuantityDomain)
    );
}

#[test]
fn independent_object_packer_cases() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|x| !x.starts_with('#'))
    {
        let v: Vec<_> = line.split_whitespace().collect();
        let mode = if v[0] == "1" { Mode::Map } else { Mode::Array };
        let asset = v[2].parse().unwrap();
        let m = v[6].parse().unwrap();
        let a = unhex(v[9]);
        let b = unhex(v[11]);
        let a = core::str::from_utf8(&a).unwrap();
        let b = core::str::from_utf8(&b).unwrap();
        let details: u8 = v[8].parse().unwrap();
        let d = (details != 0).then_some(Details {
            t: (details & 1 != 0).then_some(Trigger {
                p: a,
                a: v[10] == "1",
            }),
            s: (details & 2 != 0).then_some(b),
        });
        let actual = if v[1] == "0" {
            cancel(Cancel { asset, t: m }, mode)
        } else {
            order(
                Order {
                    asset,
                    b: v[4] == "1",
                    quantity: v[3].parse().unwrap(),
                    r: v[5] == "1",
                    m,
                    t: v[7] == "1",
                    details: d,
                },
                mode,
            )
        }
        .unwrap();
        assert_eq!(actual, unhex(v[12]), "case {count}");
        count += 1;
    }
    assert_eq!(count, 6000);
}

#[test]
fn detail_string_width_boundaries() {
    for (n, marker) in [
        (31, 0xbf),
        (32, 0xd9),
        (255, 0xd9),
        (256, 0xda),
        (65535, 0xda),
        (65536, 0xdb),
    ] {
        let s = "x".repeat(n);
        let v = Order {
            asset: 0,
            b: false,
            quantity: 0,
            r: false,
            m: 0,
            t: false,
            details: Some(Details {
                t: None,
                s: Some(&s),
            }),
        };
        let bytes = order(v, Mode::Array).unwrap();
        let pos = bytes.len()
            - n
            - if n < 32 {
                1
            } else if n < 256 {
                2
            } else if n < 65536 {
                3
            } else {
                5
            };
        assert_eq!(bytes[pos], marker, "length {n}");
    }
}
