use node115_mid_market_plan::{plan, Error, Family, Market, Time};
const USER: [u8; 20] = [7; 20];
const EPOCH: Time = Time {
    year: 1970,
    ordinal: 1,
    seconds: 0,
    nanos: 0,
};
fn market(decimals: &[u8]) -> Market<'_> {
    Market {
        count: 1,
        selected_dex: 0,
        decimals,
    }
}
#[test]
fn guard_order_and_missing_price() {
    let wrong = Market {
        count: 0,
        selected_dex: 99,
        decimals: &[],
    };
    assert_eq!(
        plan(0, wrong, (0, 0), 0, 1, USER, Family::Narrow, EPOCH),
        Err(Error::MarketIndex)
    );
    let mismatch = Market {
        count: 1,
        selected_dex: 99,
        decimals: &[],
    };
    assert_eq!(
        plan(0, mismatch, (0, 5), 0, 1, USER, Family::Narrow, EPOCH),
        Ok(None)
    );
    assert_eq!(
        plan(0, mismatch, (1, 1), 0, 1, USER, Family::Narrow, EPOCH),
        Err(Error::TickMarket)
    );
    assert_eq!(
        plan(0, market(&[7]), (1, 1), 0, 1, USER, Family::Narrow, EPOCH),
        Err(Error::Decimals)
    );
}
#[test]
fn factors_whole_tick_and_active_plan() {
    let buy = plan(
        0,
        market(&[2]),
        (2_500_000, 2_500_000),
        0,
        123,
        USER,
        Family::Narrow,
        EPOCH,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        (
            buy.limit,
            buy.size,
            buy.kind,
            buy.source,
            buy.timestamp_ms,
            buy.user
        ),
        (2_575_000, 123, 6, 1, 0, USER)
    );
    let sell = plan(
        0,
        market(&[2]),
        (2_500_000, 2_500_000),
        2,
        123,
        USER,
        Family::Narrow,
        EPOCH,
    )
    .unwrap()
    .unwrap();
    assert_eq!(sell.limit, 2_425_100);
    assert_eq!(sell.side, 2);
    let wide = plan(0, market(&[0]), (100, 100), 0, 1, USER, Family::Wide, EPOCH)
        .unwrap()
        .unwrap();
    assert_eq!((wide.limit, wide.kind, wide.source), (120, 1, 4));
}
#[test]
fn date_and_domain() {
    let t = Time {
        year: 1970,
        ordinal: 2,
        seconds: 1,
        nanos: 2_345_678,
    };
    assert_eq!(
        plan(0, market(&[0]), (1, 1), 0, 0, USER, Family::Narrow, t)
            .unwrap()
            .unwrap()
            .timestamp_ms,
        86_401_002
    );
    let before = Time {
        year: 1969,
        ordinal: 365,
        seconds: 0,
        nanos: 0,
    };
    assert_eq!(
        plan(0, market(&[0]), (1, 1), 0, 0, USER, Family::Narrow, before)
            .unwrap()
            .unwrap()
            .timestamp_ms,
        0
    );
    let invalid = Time {
        year: 2023,
        ordinal: 366,
        seconds: 0,
        nanos: 0,
    };
    assert_eq!(
        plan(0, market(&[0]), (1, 1), 0, 0, USER, Family::Narrow, invalid),
        Err(Error::InvalidTime)
    );
    assert_eq!(
        plan(0, market(&[0]), (0, 1), 0, 0, USER, Family::Narrow, invalid),
        Ok(None)
    );
}

#[test]
fn independent_exact_rational_price_and_tick_fixtures() {
    let mut cases = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|x| !x.starts_with('#'))
    {
        let c: Vec<_> = line.split_whitespace().collect();
        let bid = c[0].parse::<u64>().unwrap();
        let ask = c[1].parse::<u64>().unwrap();
        let side = c[2].parse::<u8>().unwrap();
        let decimals = c[3].parse::<u8>().unwrap();
        let family = if c[4] == "0" {
            Family::Narrow
        } else {
            Family::Wide
        };
        let expected = c[5].parse::<u64>().unwrap();
        let actual = plan(
            0,
            market(&[decimals]),
            (bid, ask),
            side,
            0,
            USER,
            family,
            EPOCH,
        )
        .unwrap()
        .unwrap();
        assert_eq!(actual.limit, expected, "case {cases}: {line}");
        cases += 1;
    }
    assert_eq!(cases, 6000);
}

#[test]
fn independent_calendar_fixtures() {
    let mut cases = 0;
    for line in include_str!("date-vectors.txt")
        .lines()
        .filter(|x| !x.starts_with('#'))
    {
        let c: Vec<_> = line.split_whitespace().collect();
        let t = Time {
            year: c[0].parse().unwrap(),
            ordinal: c[1].parse().unwrap(),
            seconds: c[2].parse().unwrap(),
            nanos: c[3].parse().unwrap(),
        };
        let expected = c[4].parse::<u64>().unwrap();
        let actual = plan(0, market(&[0]), (1, 1), 0, 0, USER, Family::Narrow, t)
            .unwrap()
            .unwrap();
        assert_eq!(actual.timestamp_ms, expected, "case {cases}: {line}");
        cases += 1;
    }
    assert_eq!(cases, 2500);
}
