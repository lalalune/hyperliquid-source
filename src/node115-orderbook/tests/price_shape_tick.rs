use node115_assets::pdi::Side;
use node115_assets::qtys::{Px, Sz};
use node115_orderbook::{PriceMove, PriceShapeContext, PriceShapeRequest, shape_order_price};

fn limit(mark: u64, side: Side, cap: u64, amount: u64) -> Px {
    let ctx = PriceShapeContext {
        user_blocked: false,
        mark_px: Px(mark),
        tick: cap,
        available_notional: u64::MAX,
        skip_min_notional: false,
        book_ref_pxs: (0, 0),
        rate_limited: false,
        now_ms: 1_000,
        last_alert_ms: 0,
        band_exempt: false,
        band_p: 0.2,
    };
    let req = PriceShapeRequest {
        user: [1; 20],
        side,
        sz: Sz(200),
        optional_ref: None,
        price_move: PriceMove::ByAmount(amount),
    };
    shape_order_price(req, ctx).unwrap().limit_px
}

#[test]
fn price_shape_uses_the_moved_side_price_to_select_the_tick() {
    // (mark, pre-grid ask, ask ladder step, pre-grid bid, bid ladder step).
    let rows = [
        (100_000, 90_000, 1, 110_000, 10),
        (100_009, 90_008, 1, 110_009, 10),
        (1_000_009, 900_008, 10, 1_100_009, 100),
        (12_345_678, 11_111_110, 1_000, 13_580_245, 1_000),
    ];
    for decimals in [5, 0, 1, 2, 3, 4, 6] {
        let cap = 10_u64.pow(6 - decimals);
        for (mark, ask, ask_step, bid, bid_step) in rows {
            for (side, price, rung) in [(Side::Ask, ask, ask_step), (Side::Bid, bid, bid_step)] {
                let tick = cap.min(rung);
                let expected = (price / tick + u64::from(side == Side::Ask)) * tick;
                assert_eq!(
                    limit(mark, side, cap, 0),
                    Px(expected),
                    "side={side:?} mark={mark} decimals={decimals}"
                );
            }
        }
    }
    // Both amount moves cross a decimal rung after applying slippage.
    assert_eq!(limit(90_900, Side::Bid, 10, 30), Px(100_020));
    assert_eq!(limit(111_200, Side::Ask, 10, 100), Px(99_991));
}

#[test]
fn both_native_tick_helpers_agree_with_the_market_cap_path() {
    let cases = include_str!(
        "../../../research/work-items/RE-014-mid-market-order-builder-115/tick_cases.tsv"
    );
    let mut checked = [0; 2];
    for line in cases.lines().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        if fields[7].starts_with("panic ") || fields[7].starts_with("index ") {
            continue; // The fixture also covers native metadata lookup failures.
        }
        let expected = fields[7].parse::<u64>().unwrap();
        let copy = match fields[0] {
            "0x5a01110" => 0,
            "0x2891f50" => 1,
            unknown => panic!("unknown helper {unknown}"),
        };
        let price = fields[3].parse().unwrap();
        let decimals: u32 = fields[4].parse().unwrap();
        let cap = 10_u64.pow(6 - decimals);
        assert_eq!(
            node115_mid_market_order_builder::tick_size_with_cap(price, cap),
            expected,
            "fixture {line}"
        );
        checked[copy] += 1;
    }
    assert_eq!(checked, [440, 440]);
}
