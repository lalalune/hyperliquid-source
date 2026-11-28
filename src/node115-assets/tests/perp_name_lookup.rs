use node115_assets::{Pdi, PerpAsset, PerpAssetMeta, PerpMeta, PerpNameLookupError};

fn row(name: &str) -> PerpAssetMeta {
    PerpAssetMeta {
        name: name.to_owned(),
        sz_decimals: 3,
        max_leverage: 10,
    }
}

#[test]
fn resolve_exchange_name_in_its_ordered_namespace() {
    let meta = PerpMeta::new(Pdi(7), ["BTC", "ETH", "ETH", "Ξ"].map(row).to_vec());
    let eth = meta.asset_by_name("ETH").unwrap();
    assert_eq!(eth, PerpAsset(70_001));
    assert_eq!(meta.sz_decimals(eth), Ok(3));
    assert_eq!(meta.asset_by_name("Ξ"), Ok(PerpAsset(70_003)));
    for missing in ["eth", "ETH ", "ＥＴＨ", ""] {
        assert_eq!(
            meta.asset_by_name(missing),
            Err(PerpNameLookupError::UnknownName(missing.into()))
        );
    }
}

#[test]
fn checked_index_follows_the_rows_actually_scanned() {
    let pdi = Pdi(u64::MAX / 10_000);
    let mut rows = vec![row("other"); 1616];
    rows[1615] = row("last");
    let mut meta = PerpMeta::new(pdi, rows);
    assert_eq!(meta.asset_by_name("last"), Ok(PerpAsset(u64::MAX)));
    assert_eq!(
        meta.asset_by_name("absent"),
        Err(PerpNameLookupError::UnknownName("absent".into()))
    );
    meta.universe.push(row("next"));
    assert_eq!(
        meta.asset_by_name("next"),
        Err(PerpNameLookupError::IndexOverflow)
    );
    assert_eq!(meta.asset_by_name("last"), Ok(PerpAsset(u64::MAX)));
    meta.pdi = Pdi(pdi.0 + 1);
    assert_eq!(
        meta.asset_by_name("other"),
        Err(PerpNameLookupError::IndexOverflow)
    );
    meta.universe.clear();
    assert_eq!(
        meta.asset_by_name(""),
        Err(PerpNameLookupError::UnknownName(String::new()))
    );
}

#[test]
fn integrated_lookup_matches_the_retained_node115_results() {
    const CASES: &str = include_str!(
        "../../../research/work-items/RE-007-node115-asset-name-lookup-evaluation/metadata-vectors.tsv"
    );
    for line in CASES.lines().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        let [page, count, names, suffix, result] = fields.as_slice() else {
            panic!("invalid lookup vector: {line}");
        };
        let count: usize = count.parse().unwrap();
        let names: Vec<_> = names.split('|').take(count).map(row).collect();
        assert_eq!(names.len(), count);
        let meta = PerpMeta::new(Pdi(page.parse().unwrap()), names);
        let expected = match *result {
            "missing" => Err(PerpNameLookupError::UnknownName((*suffix).to_owned())),
            value => Ok(PerpAsset(value.parse().unwrap())),
        };
        assert_eq!(meta.asset_by_name(suffix), expected, "{line}");
    }
}
