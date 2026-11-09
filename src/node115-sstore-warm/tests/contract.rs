use node115_sstore_warm::*;
use std::collections::BTreeMap;
const ADDRESS: Address = [0x35; 20];
const KEY: Word = [0x1234, 0x5678, 0x9abc, 0xdef0];
fn word(tag: usize) -> Word {
    match tag {
        0 => [0; 4],
        1 => [1, 0, 0, 0],
        2 => [2, 0, 0, 0],
        3 => [0, 1, 0, 0],
        4 => [0, 0, 1, 0],
        5 => [0, 0, 0, 1 << 63],
        6 => [u64::MAX; 4],
        _ => panic!("tag"),
    }
}
fn setup(original: Word, current: Word, new: Word) -> (Interpreter, Host, GasParams) {
    let i = Interpreter {
        address: ADDRESS,
        stack: vec![new, KEY],
        is_static: false,
        spec: 7,
        gas_remaining: 10_000,
        reserve: 100,
        host_spent: 0,
        refund: 0,
    };
    let slot = Slot {
        original,
        current,
        transaction_id: 9,
        warm: true,
    };
    let host = Host {
        accounts: BTreeMap::from([(
            ADDRESS,
            Account {
                flags: 0x80,
                slots: BTreeMap::from([(KEY, slot)]),
            },
        )]),
        journal: vec![],
        transaction_id: 9,
        reserve_enabled: true,
    };
    let p = GasParams {
        fixed: 100,
        set: 2000,
        reset: 500,
        clear_refund: 480,
        sentry: 230,
        restore_zero: 1900,
        restore_nonzero: 400,
        host_reserve: 800,
    };
    (i, host, p)
}
fn outcome(result: Result<Status, Fault>) -> &'static str {
    match result {
        Ok(Status::Success) => "ok",
        Ok(Status::OutOfGas) => "20",
        Ok(Status::Sentry) => "25",
        Ok(Status::Static) => "28",
        Ok(Status::StackUnderflow) => "2c",
        Err(Fault::RefundNegation) => "neg",
        Err(Fault::RefundDeltaAddition) => "delta",
        Err(Fault::RefundAccumulation) => "acc",
        _ => panic!("unexpected boundary fault"),
    }
}
#[test]
fn failure_prefixes_retain_host_effects() {
    let (mut i, mut h, p) = setup(word(0), word(0), word(5));
    i.gas_remaining = 1000;
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::OutOfGas));
    assert!(i.stack.is_empty());
    assert_eq!(i.gas_remaining, 900);
    assert_eq!(h.accounts[&ADDRESS].slots[&KEY].current, word(5));
    assert_eq!(h.accounts[&ADDRESS].flags, 0x84);
    assert_eq!(
        h.journal,
        vec![
            Journal::Touched { address: ADDRESS },
            Journal::StorageChanged {
                address: ADDRESS,
                key: KEY,
                previous: word(0)
            }
        ]
    );
    assert_eq!((i.reserve, i.host_spent, i.refund), (100, 0, 0));
    let (mut i, mut h, p) = setup(word(0), word(0), word(1));
    i.gas_remaining = 2200;
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::OutOfGas));
    assert_eq!(i.gas_remaining, 100); // fixed and variable charged; reserve gap not stored.
    assert_eq!((i.reserve, i.host_spent, i.refund), (100, 0, 0));
    assert_eq!(h.journal.len(), 2);
}
#[test]
fn early_guards_and_warm_boundary() {
    let (mut i, mut h, mut p) = setup(word(1), word(1), word(2));
    i.is_static = true;
    let before = (i.clone(), h.clone());
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::Static));
    assert_eq!((i.clone(), h.clone()), before);
    i.is_static = false;
    i.stack.clear();
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::StackUnderflow));
    assert!(h.journal.is_empty());
    i.stack = vec![word(2), KEY];
    i.gas_remaining = p.sentry;
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::Sentry));
    assert!(i.stack.is_empty());
    assert!(h.journal.is_empty());
    i.stack = vec![word(2), KEY];
    i.spec = 5;
    i.gas_remaining = 99;
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::OutOfGas));
    assert_eq!(i.gas_remaining, 99);
    assert!(h.journal.is_empty());
    i.stack = vec![word(2), KEY];
    i.gas_remaining = 10000;
    p.fixed = 0;
    h.accounts
        .get_mut(&ADDRESS)
        .unwrap()
        .slots
        .get_mut(&KEY)
        .unwrap()
        .warm = false;
    assert_eq!(
        execute(&mut i, &mut h, p),
        Err(Fault::NonresidentOrColdSlot)
    );
}
#[test]
fn reserve_release_and_refund_overflow_after_write() {
    let (mut i, mut h, p) = setup(word(0), word(1), word(0));
    i.reserve = u64::MAX - 1;
    i.host_spent = i64::MIN;
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::Success));
    assert_eq!(
        (i.reserve, i.host_spent, i.refund),
        (u64::MAX, i64::MIN, 1900)
    );
    assert_eq!(i.gas_remaining, 9900); // reserve release does not refund ordinary gas.
    let (mut i, mut h, p) = setup(word(1), word(1), word(0));
    i.refund = i64::MAX;
    assert_eq!(execute(&mut i, &mut h, p), Err(Fault::RefundAccumulation));
    assert_eq!(h.accounts[&ADDRESS].slots[&KEY].current, word(0));
    assert_eq!(i.refund, i64::MAX);
    assert_eq!(i.gas_remaining, 9400);
}
#[test]
fn same_value_and_other_storage_preserved() {
    let (mut i, mut h, p) = setup(word(3), word(3), word(3));
    let other = [u64::MAX; 4];
    let slot = h.accounts[&ADDRESS].slots[&KEY];
    h.accounts
        .get_mut(&ADDRESS)
        .unwrap()
        .slots
        .insert(other, slot);
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::Success));
    assert_eq!(h.journal, vec![Journal::Touched { address: ADDRESS }]);
    assert_eq!(h.accounts[&ADDRESS].slots[&other], slot);
    i.stack = vec![word(3), KEY];
    assert_eq!(execute(&mut i, &mut h, p), Ok(Status::Success));
    assert_eq!(h.journal.len(), 1);
}
#[test]
fn integer_state_reference_cases() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let (a, b) = line.split_once(" | ").unwrap();
        let x: Vec<i128> = a.split_whitespace().map(|s| s.parse().unwrap()).collect();
        let e: Vec<_> = b.split_whitespace().collect();
        let n = |k: usize| e[k].parse::<i128>().unwrap();
        let (mut i, mut h, mut p) = setup(
            word(x[5] as usize),
            word(x[6] as usize),
            word(x[7] as usize),
        );
        i.spec = x[0] as u8;
        i.is_static = x[1] != 0;
        let len = x[2] as usize;
        i.stack = vec![[99; 4]; len];
        if len >= 2 {
            i.stack[len - 1] = KEY;
            i.stack[len - 2] = word(x[7] as usize);
        }
        h.reserve_enabled = x[3] != 0;
        h.accounts.get_mut(&ADDRESS).unwrap().flags = x[4] as u8;
        i.gas_remaining = x[8] as u64;
        i.reserve = x[9] as u64;
        i.host_spent = x[10] as i64;
        i.refund = x[11] as i64;
        p.fixed = x[12] as u64;
        p.set = x[13] as u64;
        p.reset = x[14] as u64;
        p.clear_refund = x[15] as i64;
        p.sentry = x[16] as u64;
        p.restore_zero = x[17] as i64;
        p.restore_nonzero = x[18] as i64;
        p.host_reserve = x[19] as u64;
        let original_stack = i.stack.clone();
        let got = execute(&mut i, &mut h, p);
        assert_eq!(outcome(got), e[0], "case {count}");
        assert_eq!(
            (
                i.gas_remaining,
                i.reserve,
                i.host_spent,
                i.refund,
                i.stack.len()
            ),
            (
                n(1) as u64,
                n(2) as u64,
                n(3) as i64,
                n(4) as i64,
                n(5) as usize
            ),
            "case {count}"
        );
        let acc = &h.accounts[&ADDRESS];
        assert_eq!(
            (acc.flags, acc.slots[&KEY].current),
            (n(6) as u8, word(n(7) as usize)),
            "case {count}"
        );
        assert_eq!(acc.slots[&KEY].original, word(x[5] as usize));
        let mut expected = vec![];
        let mask = n(8);
        if mask & 1 != 0 {
            expected.push(Journal::Touched { address: ADDRESS });
        }
        if mask & 2 != 0 {
            expected.push(Journal::StorageChanged {
                address: ADDRESS,
                key: KEY,
                previous: word(x[6] as usize),
            });
        }
        assert_eq!(h.journal, expected, "case {count}");
        let expected_stack = if x[1] != 0 || len < 2 {
            original_stack.as_slice()
        } else {
            &original_stack[..len - 2]
        };
        assert_eq!(i.stack, expected_stack, "case {count}");
        count += 1;
    }
    assert_eq!(count, 16000);
}
