//! Selected successful-Content field assembly at node #115 0x2021f80.
//! Individual values have already passed the native field value decoders.
use node115_borrow_lend_codec::{BorrowLendField, Operation};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub operation: Operation,
    pub token: u64,
    pub amount: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Operation(Operation),
    Token(u64),
    Amount(Option<Vec<u8>>),
    UnclosedValue,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    UnknownField,
    Duplicate(BorrowLendField),
    Missing(BorrowLendField),
    BeforeValueDecoder(BorrowLendField),
    InvalidSequenceLength(usize),
}

/// Map field keys are supplied as decoded valid UTF-8. Other Content key forms,
/// individual value decoding and error-object construction remain boundaries.
/// Unknown and duplicate keys are decided before their value is inspected.
pub fn assemble_map(entries: Vec<(&str, Value)>) -> Result<Action, Stop> {
    let (mut operation, mut token, mut amount) = (None, None, None);
    for (key, value) in entries {
        let field = BorrowLendField::from_name(key).ok_or(Stop::UnknownField)?;
        match field {
            BorrowLendField::Operation => {
                if operation.is_some() {
                    return Err(Stop::Duplicate(field));
                }
                if let Value::Operation(value) = value {
                    operation = Some(value);
                } else {
                    return Err(Stop::BeforeValueDecoder(field));
                }
            }
            BorrowLendField::Token => {
                if token.is_some() {
                    return Err(Stop::Duplicate(field));
                }
                if let Value::Token(value) = value {
                    token = Some(value);
                } else {
                    return Err(Stop::BeforeValueDecoder(field));
                }
            }
            BorrowLendField::Amount => {
                if amount.is_some() {
                    return Err(Stop::Duplicate(field));
                }
                if let Value::Amount(value) = value {
                    amount = Some(value);
                } else {
                    return Err(Stop::BeforeValueDecoder(field));
                }
            }
        }
    }
    let operation = operation.ok_or(Stop::Missing(BorrowLendField::Operation))?;
    let token = token.ok_or(Stop::Missing(BorrowLendField::Token))?;
    Ok(Action {
        operation,
        token,
        amount: amount.unwrap_or(None),
    })
}

/// The Content sequence form requires exactly three decoded elements, unlike
/// the map form's default for an absent amount field.
pub fn assemble_sequence(values: Vec<Value>) -> Result<Action, Stop> {
    let mut i = values.into_iter();
    let operation = match i.next() {
        None => return Err(Stop::InvalidSequenceLength(0)),
        Some(Value::Operation(v)) => v,
        Some(_) => return Err(Stop::BeforeValueDecoder(BorrowLendField::Operation)),
    };
    let token = match i.next() {
        None => return Err(Stop::InvalidSequenceLength(1)),
        Some(Value::Token(v)) => v,
        Some(_) => return Err(Stop::BeforeValueDecoder(BorrowLendField::Token)),
    };
    let amount = match i.next() {
        None => return Err(Stop::InvalidSequenceLength(2)),
        Some(Value::Amount(v)) => v,
        Some(_) => return Err(Stop::BeforeValueDecoder(BorrowLendField::Amount)),
    };
    let trailing = i.count();
    if trailing != 0 {
        return Err(Stop::InvalidSequenceLength(3 + trailing));
    }
    Ok(Action {
        operation,
        token,
        amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn field_orders_and_all_operation_variants() {
        for op in Operation::ALL {
            for order in [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ] {
                let entries = order
                    .into_iter()
                    .map(|i| match i {
                        0 => ("operation", Value::Operation(op)),
                        1 => ("token", Value::Token(u64::MAX)),
                        _ => ("amount", Value::Amount(Some(vec![0, 255]))),
                    })
                    .collect();
                assert_eq!(
                    assemble_map(entries),
                    Ok(Action {
                        operation: op,
                        token: u64::MAX,
                        amount: Some(vec![0, 255])
                    })
                );
            }
        }
    }
    #[test]
    fn missing_and_null_amount_are_distinct_from_duplicate_presence() {
        let op = Operation::Borrow;
        let base = vec![
            ("operation", Value::Operation(op)),
            ("token", Value::Token(7)),
        ];
        assert_eq!(
            assemble_map(base.clone()),
            Ok(Action {
                operation: op,
                token: 7,
                amount: None
            })
        );
        let mut null = base.clone();
        null.push(("amount", Value::Amount(None)));
        assert_eq!(
            assemble_map(null.clone()),
            Ok(Action {
                operation: op,
                token: 7,
                amount: None
            })
        );
        null.push(("amount", Value::UnclosedValue));
        assert_eq!(
            assemble_map(null),
            Err(Stop::Duplicate(BorrowLendField::Amount))
        );
        assert_eq!(
            assemble_map(vec![]),
            Err(Stop::Missing(BorrowLendField::Operation))
        );
        assert_eq!(
            assemble_map(vec![("operation", Value::Operation(op))]),
            Err(Stop::Missing(BorrowLendField::Token))
        );
        assert_eq!(
            assemble_map(vec![("unknown", Value::UnclosedValue)]),
            Err(Stop::UnknownField)
        );
    }
    #[test]
    fn exact_sequence_arity_and_predecoder_boundaries() {
        let vals = vec![
            Value::Operation(Operation::Repay),
            Value::Token(1),
            Value::Amount(None),
        ];
        assert!(assemble_sequence(vals.clone()).is_ok());
        for n in 0..3 {
            assert_eq!(
                assemble_sequence(vals[..n].to_vec()),
                Err(Stop::InvalidSequenceLength(n))
            );
        }
        let mut extra = vals;
        extra.push(Value::UnclosedValue);
        assert_eq!(
            assemble_sequence(extra),
            Err(Stop::InvalidSequenceLength(4))
        );
        assert_eq!(
            assemble_map(vec![("token", Value::UnclosedValue)]),
            Err(Stop::BeforeValueDecoder(BorrowLendField::Token))
        );
    }
}
