use info_api::response::spot::{write_spot_state, Balance, EvmEscrow, SpotState, TokenValues};
use std::io::{self, Write};

fn json(state: &SpotState<'_>) -> String {
    let mut out = Vec::new();
    write_spot_state(&mut out, state).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn empty_standard_and_documented_balances() {
    assert_eq!(json(&SpotState::default()), r#"{"balances":[]}"#);
    let rows = [
        Balance {
            coin: "USDC",
            token: Some(0),
            total: "14.625485",
            hold: "0.0",
            entry_ntl: "0.0",
            ..Default::default()
        },
        Balance {
            coin: "PURR",
            token: Some(1),
            total: "2000.0",
            hold: "0.0",
            entry_ntl: "1234.56",
            ..Default::default()
        },
        Balance {
            coin: "+1230",
            total: "25.0",
            hold: "0.0",
            entry_ntl: "12.5",
            ..Default::default()
        },
    ];
    assert_eq!(
        json(&SpotState {
            balances: &rows,
            ..Default::default()
        }),
        concat!(
            r#"{"balances":[{"coin":"USDC","token":0,"total":"14.625485","hold":"0.0","entryNtl":"0.0"},"#,
            r#"{"coin":"PURR","token":1,"total":"2000.0","hold":"0.0","entryNtl":"1234.56"},"#,
            r#"{"coin":"+1230","total":"25.0","hold":"0.0","entryNtl":"12.5"}]}"#
        )
    );
}

#[test]
fn preserve_field_sequence_portfolio_presence_empty_maps_and_escaping() {
    let rows = [Balance {
        coin: "é\n\"\\\u{1}",
        token: Some(8),
        total: "1.0",
        hold: "2.0",
        entry_ntl: "3.0",
        spot_hold: Some("0.0"),
        ltv: Some("0.75"),
        borrowed: Some("1.3"),
        supplied: Some("0.4"),
    }];
    let escrows = [EvmEscrow {
        coin: "E",
        token: 4,
        total: "2.0",
    }];
    let borrow = TokenValues::from([(8, "0.2"), (2, "0.7")]);
    let supply = TokenValues::new();
    let available = TokenValues::from([(5, "1.0")]);
    let state = SpotState {
        portfolio_margin_enabled: true,
        balances: &rows,
        evm_escrows: &escrows,
        portfolio_margin_ratio: Some("0.0"),
        token_to_portfolio_borrow_ratio: Some(&borrow),
        token_to_portfolio_supply_ratio: Some(&supply),
        token_to_available_after_maintenance: Some(&available),
    };
    assert_eq!(
        json(&state),
        concat!(
            r#"{"portfolioMarginEnabled":true,"balances":[{"coin":"é\n\"\\\u0001","token":8,"total":"1.0","hold":"2.0","entryNtl":"3.0","#,
            r#""spotHold":"0.0","ltv":"0.75","borrowed":"1.3","supplied":"0.4"}],"evmEscrows":[{"coin":"E","token":4,"total":"2.0"}],"#,
            r#""portfolioMarginRatio":"0.0","tokenToPortfolioBorrowRatio":[[2,"0.7"],[8,"0.2"]],"tokenToPortfolioSupplyRatio":[],"#,
            r#""tokenToAvailableAfterMaintenance":[[5,"1.0"]]}"#
        )
    );
}

#[test]
fn a_writer_failure_preserves_only_the_written_prefix() {
    struct Limited(Vec<u8>);
    impl Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(11 - self.0.len());
            if count == 0 {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.0.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut out = Limited(Vec::new());
    let err = write_spot_state(&mut out, &SpotState::default()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(out.0, &br#"{"balances":[]}"#[..11]);
}
