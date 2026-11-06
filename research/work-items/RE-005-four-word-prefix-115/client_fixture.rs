use node115_four_word_prefix::{Decoder, Error, Fields};
use node115_u64_reader_state::Error as R;
#[test]
fn frozen_target_cases() {
    {
        let input: &[u8] = &[0];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 0"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 0),
            "sealed state 0"
        );
    }
    {
        let input: &[u8] = &[0];
        let mut d = Decoder::new(input, Some(0), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 1"
        );
    }
    {
        let input: &[u8] = &[0];
        let mut d = Decoder::new(input, Some(8), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 16),
            "sealed state 2"
        );
    }
    {
        let input: &[u8] = &[0, 5];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 5"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 0),
            "sealed state 5"
        );
    }
    {
        let input: &[u8] = &[0, 5, 42];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 10"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 0),
            "sealed state 10"
        );
    }
    {
        let input: &[u8] = &[0, 5, 42];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 13"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 32),
            "sealed state 13"
        );
    }
    {
        let input: &[u8] = &[0, 5, 42, 79];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 15"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (4, 0),
            "sealed state 15"
        );
    }
    {
        let input: &[u8] = &[0, 5, 42, 79];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 18"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (4, 33),
            "sealed state 18"
        );
    }
    {
        let input: &[u8] = &[0, 5, 42, 79, 116];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 116 }),
            "sealed row 20"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 0),
            "sealed state 20"
        );
    }
    {
        let input: &[u8] = &[0, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 116 }),
            "sealed row 23"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 23"
        );
    }
    {
        let input: &[u8] = &[1, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 116 }),
            "sealed row 83"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 83"
        );
    }
    {
        let input: &[u8] = &[17, 5, 42, 79, 116, 153, 190, 227, 8, 45];
        let mut d = Decoder::new(input, Some(0), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 166");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 166"
        );
    }
    {
        let input: &[u8] = &[251, 5];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 249"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 8),
            "sealed state 249"
        );
    }
    {
        let input: &[u8] = &[251, 5, 42];
        let mut d = Decoder::new(input, Some(8), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 252");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 16),
            "sealed state 252"
        );
    }
    {
        let input: &[u8] = &[251, 5, 42, 79, 116];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 260"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 0),
            "sealed state 260"
        );
    }
    {
        let input: &[u8] = &[251, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 263"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 32),
            "sealed state 263"
        );
    }
    {
        let input: &[u8] = &[251, 5, 42, 79, 116, 153];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 265"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 0),
            "sealed state 265"
        );
    }
    {
        let input: &[u8] = &[251, 5, 42, 79, 116, 153];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 268"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 33),
            "sealed state 268"
        );
    }
    {
        let input: &[u8] = &[251, 5, 42, 79, 116, 153, 190];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 190 }),
            "sealed row 270"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (7, 0),
            "sealed state 270"
        );
    }
    {
        let input: &[u8] = &[251, 5, 42, 79, 116, 153, 190];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 190 }),
            "sealed row 273"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (7, 33),
            "sealed state 273"
        );
    }
    {
        let input: &[u8] = &[252, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(8), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 322");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 16),
            "sealed state 322"
        );
    }
    {
        let input: &[u8] = &[252, 5, 42, 79, 116, 153, 190];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 330"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (7, 0),
            "sealed state 330"
        );
    }
    {
        let input: &[u8] = &[252, 5, 42, 79, 116, 153, 190];
        let mut d = Decoder::new(input, Some(8), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 332");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 16),
            "sealed state 332"
        );
    }
    {
        let input: &[u8] = &[252, 5, 42, 79, 116, 153, 190];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 333"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (7, 32),
            "sealed state 333"
        );
    }
    {
        let input: &[u8] = &[252, 5, 42, 79, 116, 153, 190, 227];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 335"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (8, 0),
            "sealed state 335"
        );
    }
    {
        let input: &[u8] = &[252, 5, 42, 79, 116, 153, 190, 227];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 338"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (8, 33),
            "sealed state 338"
        );
    }
    {
        let input: &[u8] = &[252, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 8 }),
            "sealed row 340"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (9, 0),
            "sealed state 340"
        );
    }
    {
        let input: &[u8] = &[252, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 8 }),
            "sealed row 343"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (9, 33),
            "sealed state 343"
        );
    }
    {
        let input: &[u8] = &[253, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 400"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (9, 0),
            "sealed state 400"
        );
    }
    {
        let input: &[u8] = &[253, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(8), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 402");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (9, 16),
            "sealed state 402"
        );
    }
    {
        let input: &[u8] = &[253, 5, 42, 79, 116, 153, 190, 227, 8, 45];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 405"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (10, 0),
            "sealed state 405"
        );
    }
    {
        let input: &[u8] = &[253, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 410"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (11, 0),
            "sealed state 410"
        );
    }
    {
        let input: &[u8] = &[253, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 413"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (11, 32),
            "sealed state 413"
        );
    }
    {
        let input: &[u8] = &[253, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 415"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (12, 0),
            "sealed state 415"
        );
    }
    {
        let input: &[u8] = &[253, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 418"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (12, 33),
            "sealed state 418"
        );
    }
    {
        let input: &[u8] = &[254];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 4
            })),
            "sealed row 420"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 0),
            "sealed state 420"
        );
    }
    {
        let input: &[u8] = &[254, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 2,
                found_raw: 4
            })),
            "sealed row 460"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 0),
            "sealed state 460"
        );
    }
    {
        let input: &[u8] = &[255, 5, 42, 79];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 12
            })),
            "sealed row 498"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 8),
            "sealed state 498"
        );
    }
    {
        let input: &[u8] = &[17, 0];
        let mut d = Decoder::new(input, Some(16), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 543");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 24),
            "sealed state 543"
        );
    }
    {
        let input: &[u8] = &[17, 0, 5, 42, 79, 116, 153, 190];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 79 }),
            "sealed row 581"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 581"
        );
    }
    {
        let input: &[u8] = &[17, 1, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 79 }),
            "sealed row 664"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 664"
        );
    }
    {
        let input: &[u8] = &[17, 17, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82];
        let mut d = Decoder::new(input, Some(16), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 747");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 24),
            "sealed state 747"
        );
    }
    {
        let input: &[u8] = &[17, 251];
        let mut d = Decoder::new(input, Some(8), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 830");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 16),
            "sealed state 830"
        );
    }
    {
        let input: &[u8] = &[17, 251, 5, 42];
        let mut d = Decoder::new(input, Some(16), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 843");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (4, 24),
            "sealed state 843"
        );
    }
    {
        let input: &[u8] = &[17, 252, 5, 42];
        let mut d = Decoder::new(input, Some(0), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 913");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 913"
        );
    }
    {
        let input: &[u8] = &[17, 252, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(16), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 927");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 24),
            "sealed state 927"
        );
    }
    {
        let input: &[u8] = &[17, 253, 5, 42, 79, 116];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 4 })),
            "sealed row 996"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 0),
            "sealed state 996"
        );
    }
    {
        let input: &[u8] = &[17, 253, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(16), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1023");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (10, 24),
            "sealed state 1023"
        );
    }
    {
        let input: &[u8] = &[17, 253, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 119 }),
            "sealed row 1038"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (13, 0),
            "sealed state 1038"
        );
    }
    {
        let input: &[u8] = &[17, 253, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 119 }),
            "sealed row 1042"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (13, 33),
            "sealed state 1042"
        );
    }
    {
        let input: &[u8] = &[17, 254];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 4
            })),
            "sealed row 1044"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 0),
            "sealed state 1044"
        );
    }
    {
        let input: &[u8] = &[17, 254, 5, 42, 79, 116, 153];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 4
            })),
            "sealed row 1079"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 16),
            "sealed state 1079"
        );
    }
    {
        let input: &[u8] = &[17, 255, 5, 42, 79, 116, 153, 190, 227];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 12
            })),
            "sealed row 1162"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 16),
            "sealed state 1162"
        );
    }
    {
        let input: &[u8] = &[17, 29, 0];
        let mut d = Decoder::new(input, Some(24), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1191");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 32),
            "sealed state 1191"
        );
    }
    {
        let input: &[u8] = &[17, 29, 0, 5, 42, 79, 116, 153, 190, 227, 8, 45];
        let mut d = Decoder::new(input, Some(24), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1245");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 32),
            "sealed state 1245"
        );
    }
    {
        let input: &[u8] = &[17, 29, 1, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119];
        let mut d = Decoder::new(input, Some(16), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1328");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 24),
            "sealed state 1328"
        );
    }
    {
        let input: &[u8] = &[17, 29, 250, 5];
        let mut d = Decoder::new(input, Some(0), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1411");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 1411"
        );
    }
    {
        let input: &[u8] = &[17, 29, 251, 5, 42];
        let mut d = Decoder::new(input, Some(24), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1491");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 32),
            "sealed state 1491"
        );
    }
    {
        let input: &[u8] = &[17, 29, 251, 5, 42, 79];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 1494"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 0),
            "sealed state 1494"
        );
    }
    {
        let input: &[u8] = &[17, 29, 252, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(24), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1575");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (7, 32),
            "sealed state 1575"
        );
    }
    {
        let input: &[u8] = &[17, 29, 252, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 1577"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (7, 32),
            "sealed state 1577"
        );
    }
    {
        let input: &[u8] = &[17, 29, 253, 5, 42, 79, 116, 153, 190];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 2 })),
            "sealed row 1660"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 24),
            "sealed state 1660"
        );
    }
    {
        let input: &[u8] = &[17, 29, 253, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(24), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1671");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (11, 32),
            "sealed state 1671"
        );
    }
    {
        let input: &[u8] = &[17, 29, 254];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 4
            })),
            "sealed row 1692"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 0),
            "sealed state 1692"
        );
    }
    {
        let input: &[u8] = &[17, 29, 254, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(24), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 2,
                found_raw: 4
            })),
            "sealed row 1743"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 24),
            "sealed state 1743"
        );
    }
    {
        let input: &[u8] = &[17, 29, 255, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82];
        let mut d = Decoder::new(input, Some(16), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1826");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 24),
            "sealed state 1826"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 0];
        let mut d = Decoder::new(input, Some(32), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1839");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (4, 33),
            "sealed state 1839"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 1];
        let mut d = Decoder::new(input, Some(0), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 1909");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 1909"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 17, 5, 42];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 5 }),
            "sealed row 1992"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 0),
            "sealed state 1992"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 250, 5, 42, 79];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 5 }),
            "sealed row 2075"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 2075"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 251, 5, 42];
        let mut d = Decoder::new(input, Some(32), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2139");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 33),
            "sealed state 2139"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 251, 5, 42, 79, 116, 153];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 79 }),
            "sealed row 2158"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (7, 33),
            "sealed state 2158"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 252, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(32), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2223");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (8, 33),
            "sealed state 2223"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 252, 5, 42, 79, 116, 153, 190, 227];
        let mut d = Decoder::new(input, Some(32), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2241");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (8, 33),
            "sealed state 2241"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 253, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(32), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2319");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (12, 33),
            "sealed state 2319"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 253, 5, 42, 79, 116, 153, 190, 227, 8, 45];
        let mut d = Decoder::new(input, Some(24), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2324");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 32),
            "sealed state 2324"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 254];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 4
            })),
            "sealed row 2340"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (4, 0),
            "sealed state 2340"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 254];
        let mut d = Decoder::new(input, Some(32), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 4
            })),
            "sealed row 2343"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (4, 32),
            "sealed state 2343"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 254, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(32), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 2,
                found_raw: 4
            })),
            "sealed row 2391"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 32),
            "sealed state 2391"
        );
    }
    {
        let input: &[u8] = &[
            17, 29, 43, 254, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119,
        ];
        let mut d = Decoder::new(input, Some(0), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2407");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 2407"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 0];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(0)
            }),
            "sealed row 2484"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 0),
            "sealed state 2484"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 0];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(0)
            }),
            "sealed row 2489"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 41),
            "sealed state 2489"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 0, 5];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(0)
            }),
            "sealed row 2490"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 0),
            "sealed state 2490"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 1, 5, 42];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(1)
            }),
            "sealed row 2573"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 41),
            "sealed state 2573"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 17, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2656");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 41),
            "sealed state 2656"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 250, 5, 42, 79, 116, 153, 190];
        let mut d = Decoder::new(input, Some(40), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2739");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 41),
            "sealed state 2739"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 251, 5, 42];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(10757)
            }),
            "sealed row 2784"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (8, 0),
            "sealed state 2784"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 251, 5, 42];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(10757)
            }),
            "sealed row 2789"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (8, 41),
            "sealed state 2789"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 251, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(32), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2822");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (4, 33),
            "sealed state 2822"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 252, 5, 42, 79, 116];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(1951345157)
            }),
            "sealed row 2868"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (10, 0),
            "sealed state 2868"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 252, 5, 42, 79, 116];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(1951345157)
            }),
            "sealed row 2873"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (10, 41),
            "sealed state 2873"
        );
    }
    {
        let input: &[u8] = &[
            17, 29, 43, 61, 1, 252, 5, 42, 79, 116, 153, 190, 227, 8, 45, 82,
        ];
        let mut d = Decoder::new(input, Some(0), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 2905");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 2905"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 253, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(640565138307361285)
            }),
            "sealed row 2964"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (14, 0),
            "sealed state 2964"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 253, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: Some(640565138307361285)
            }),
            "sealed row 2969"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (14, 41),
            "sealed state 2969"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 254];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 4
            })),
            "sealed row 2988"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 0),
            "sealed state 2988"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 254];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 4
            })),
            "sealed row 2993"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 41),
            "sealed state 2993"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 254, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 2,
                found_raw: 4
            })),
            "sealed row 3036"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 0),
            "sealed state 3036"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 254, 5, 42, 79, 116, 153, 190, 227, 8];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 2,
                found_raw: 4
            })),
            "sealed row 3041"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 41),
            "sealed state 3041"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 255, 5];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::Invalid {
                expected_raw: 3,
                found_raw: 12
            })),
            "sealed row 3071"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (6, 41),
            "sealed state 3071"
        );
    }
    {
        let input: &[u8] = &[];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Read(R::UnexpectedEnd { additional: 1 })),
            "sealed row 3132"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 0),
            "sealed state 3132"
        );
    }
    {
        let input: &[u8] = &[17, 29];
        let mut d = Decoder::new(input, Some(8), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 3154");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 16),
            "sealed state 3154"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 0];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: None
            }),
            "sealed row 3188"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 0),
            "sealed state 3188"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 0];
        let mut d = Decoder::new(input, Some(33), 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: None
            }),
            "sealed row 3196"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 3196"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 0, 253, 255, 255, 255];
        let mut d = Decoder::new(input, Some(7), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 3237");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 3237"
        );
    }
    {
        let input: &[u8] = &[
            17, 29, 43, 61, 0, 253, 255, 255, 255, 255, 255, 255, 255, 255, 137, 171,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [17, 29, 43, 61],
                tail: None
            }),
            "sealed row 3320"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 0),
            "sealed state 3320"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 1, 253, 255, 255, 255, 255, 255];
        let mut d = Decoder::new(input, Some(16), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 3403");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (2, 24),
            "sealed state 3403"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 2, 253];
        let mut d = Decoder::new(input, Some(15), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 3486");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 16),
            "sealed state 3486"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 2, 253, 255, 255, 255, 255, 255, 255, 255];
        let mut d = Decoder::new(input, Some(8), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 3569");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (1, 16),
            "sealed state 3569"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 5, 253, 255, 255];
        let mut d = Decoder::new(input, Some(7), 0);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 3652");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 8),
            "sealed state 3652"
        );
    }
    {
        let input: &[u8] = &[
            17, 29, 43, 61, 5, 253, 255, 255, 255, 255, 255, 255, 255, 255, 137,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 5 }),
            "sealed row 3735"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 0),
            "sealed state 3735"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 254, 253, 255, 255, 255];
        let mut d = Decoder::new(input, Some(18446744073709551615), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 254 }),
            "sealed row 3818"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 3818"
        );
    }
    {
        let input: &[u8] = &[
            17, 29, 43, 61, 254, 253, 255, 255, 255, 255, 255, 255, 255, 255, 137, 171,
        ];
        let mut d = Decoder::new(input, Some(41), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 254 }),
            "sealed row 3901"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 3901"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 255, 253, 255, 255, 255, 255, 255];
        let mut d = Decoder::new(input, Some(40), 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 255 }),
            "sealed row 3984"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (5, 33),
            "sealed state 3984"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 0, 73];
        let mut d = Decoder::new(input, Some(32), 7);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 4067");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (3, 39),
            "sealed state 4067"
        );
    }
    {
        let input: &[u8] = &[17, 29, 43, 61, 2, 73];
        let mut d = Decoder::new(input, Some(0), 18446744073709551583);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row 4150");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (0, 18446744073709551591),
            "sealed state 4150"
        );
    }
    {
        let input: &[u8] = &[251, 0, 0, 251, 0, 0, 251, 0, 0, 251, 0, 0, 0];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [0, 0, 0, 0],
                tail: None
            }),
            "sealed row 4233"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (13, 0),
            "sealed state 4233"
        );
    }
    {
        let input: &[u8] = &[
            251, 0, 0, 251, 0, 0, 251, 0, 0, 251, 0, 0, 1, 253, 255, 255, 255, 255, 255, 255, 255,
            255,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [0, 0, 0, 0],
                tail: Some(18446744073709551615)
            }),
            "sealed row 4235"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (22, 0),
            "sealed state 4235"
        );
    }
    {
        let input: &[u8] = &[
            252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 0,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [0, 0, 0, 0],
                tail: None
            }),
            "sealed row 4239"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (21, 0),
            "sealed state 4239"
        );
    }
    {
        let input: &[u8] = &[
            252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 1, 253, 255, 255,
            255, 255, 255, 255, 255, 255,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [0, 0, 0, 0],
                tail: Some(18446744073709551615)
            }),
            "sealed row 4241"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (30, 0),
            "sealed state 4241"
        );
    }
    {
        let input: &[u8] = &[
            252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 252, 0, 0, 0, 0, 2,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 2 }),
            "sealed row 4243"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (21, 0),
            "sealed state 4243"
        );
    }
    {
        let input: &[u8] = &[
            253, 0, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0, 0,
            253, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [0, 0, 0, 0],
                tail: None
            }),
            "sealed row 4245"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (37, 0),
            "sealed state 4245"
        );
    }
    {
        let input: &[u8] = &[
            253, 0, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0, 0,
            253, 0, 0, 0, 0, 0, 0, 0, 0, 1, 253, 255, 255, 255, 255, 255, 255, 255, 255,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [0, 0, 0, 0],
                tail: Some(18446744073709551615)
            }),
            "sealed row 4247"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (46, 0),
            "sealed state 4247"
        );
    }
    {
        let input: &[u8] = &[
            253, 0, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0, 0,
            253, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 2 }),
            "sealed row 4249"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (37, 0),
            "sealed state 4249"
        );
    }
    {
        let input: &[u8] = &[
            250, 251, 251, 0, 252, 0, 0, 1, 0, 253, 255, 255, 255, 255, 255, 255, 255, 255, 0,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [250, 251, 65536, 18446744073709551615],
                tail: None
            }),
            "sealed row 4251"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (19, 0),
            "sealed state 4251"
        );
    }
    {
        let input: &[u8] = &[
            250, 251, 251, 0, 252, 0, 0, 1, 0, 253, 255, 255, 255, 255, 255, 255, 255, 255, 1, 253,
            255, 255, 255, 255, 255, 255, 255, 255,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Ok(Fields {
                words: [250, 251, 65536, 18446744073709551615],
                tail: Some(18446744073709551615)
            }),
            "sealed row 4253"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (28, 0),
            "sealed state 4253"
        );
    }
    {
        let input: &[u8] = &[
            250, 251, 251, 0, 252, 0, 0, 1, 0, 253, 255, 255, 255, 255, 255, 255, 255, 255, 2,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 2 }),
            "sealed row 4255"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (19, 0),
            "sealed state 4255"
        );
    }
    {
        let input: &[u8] = &[
            253, 1, 0, 0, 0, 0, 0, 0, 0, 253, 2, 0, 0, 0, 0, 0, 0, 0, 253, 3, 0, 0, 0, 0, 0, 0, 0,
            253, 4, 0, 0, 0, 0, 0, 0, 0, 2, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
            122,
        ];
        let mut d = Decoder::new(input, None, 0);
        assert_eq!(
            d.decode(),
            Err(Error::Mode { found_raw: 2 }),
            "sealed row 4292"
        );
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (37, 0),
            "sealed state 4292"
        );
    }
    // Added from unchanged pre-Rust sealed row4142 after a wrap mutant
    // escaped the first127-case client sample. No native expectation changed.
    {
        let input = &[17, 29, 43, 61, 0, 73];
        let mut d = Decoder::new(input, Some(18446744073709551615), 18446744073709551583);
        assert_eq!(d.decode(), Err(Error::Read(R::Limit)), "sealed row4142");
        assert_eq!(
            (input.len() - d.remaining().len(), d.charged()),
            (4, 18446744073709551615)
        );
    }
}
