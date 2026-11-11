use AdmissionClass::*;
use node115_action_admission_binding::*;

#[test]
fn named_policy_boundaries_preserve_exact_wire_spelling() {
    for (name, index, class) in [
        ("SetGlobalAction", 25, ValidatorOnly),
        ("VoteGlobalAction", 20, ValidatorOrListedAddress),
        ("ForceIncreaseEpochAction", 9, AnySigner),
        ("RegisterValidatorAction", 16, AnySigner),
        ("approveAgent", 1, AnySigner),
        ("order", 14, ResolveKnownUser),
        ("noop", 0, ResolveKnownUser),
        ("SystemBoleAction", 56, Refused),
        ("SystemSpotSendAction", 57, Refused),
        ("SystemUsdClassTransferAction", 59, Refused),
        ("SystemApproveBuilderFeeAction", 70, Refused),
        ("SystemSendAssetAction", 71, Refused),
    ] {
        let action = from_wire_name(name).unwrap();
        assert_eq!((action.index, action.admission), (index, class));
    }
    for name in [
        "forceIncreaseEpoch",
        "ForceIncreaseEpoch",
        "voteGlobal",
        "setGlobal",
        "Order",
        "order\0",
        " order",
        "type",
        "Action",
        "",
    ] {
        assert_eq!(from_wire_name(name), None);
    }
}

#[test]
fn every_below_base_word_is_a_noncanonical_index_twenty_alias() {
    for word in 0..0x86 {
        let binding = from_internal_word(word).unwrap();
        assert!(binding.below_base_alias);
        assert_eq!(binding.action.wire_name, "VoteGlobalAction");
        assert_eq!(binding.action.admission, ValidatorOrListedAddress);
    }
    let nominal = from_internal_word(0x9a).unwrap();
    assert!(!nominal.below_base_alias);
    assert_eq!(nominal.action, from_internal_word(0).unwrap().action);
}

#[test]
fn indices_and_nominal_words_are_distinct_domains() {
    assert_eq!(from_index(0).unwrap().wire_name, "noop");
    assert_eq!(
        from_internal_word(0).unwrap().action.wire_name,
        "VoteGlobalAction"
    );
    assert_eq!(from_internal_word(0x86).unwrap().action.wire_name, "noop");
    assert_eq!(from_index(91).unwrap().wire_name, "cDeposit2");
    assert_eq!(
        from_internal_word(0xe1).unwrap().action.wire_name,
        "cDeposit2"
    );
    for word in [0xe2, 0xff, 0x100, 0x1_0000_0086, u64::MAX] {
        assert_eq!(from_internal_word(word), Err(OutsideRecoveredDomain));
    }
    for index in [92, 134, 255, u64::MAX] {
        assert_eq!(from_index(index), None);
    }
}

#[test]
fn all_actions_are_unique_and_partition_into_the_five_observed_classes() {
    let mut counts = [0; 5];
    for (i, action) in ACTIONS.iter().enumerate() {
        assert_eq!(action.index as usize, i);
        assert_eq!(from_wire_name(action.wire_name), Some(action));
        assert_eq!(
            from_internal_word(action.nominal_tag()).unwrap().action,
            action
        );
        assert!(
            !from_internal_word(action.nominal_tag())
                .unwrap()
                .below_base_alias
        );
        assert!(
            ACTIONS[..i]
                .iter()
                .all(|old| old.wire_name != action.wire_name)
        );
        counts[action.admission as usize] += 1;
    }
    assert_eq!(counts, [1, 1, 38, 47, 5]);
}

#[test]
fn identity_prefix_and_semantically_suggestive_names_do_not_determine_class() {
    assert_eq!(
        from_wire_name("validatorL1Vote").unwrap().admission,
        AnySigner
    );
    assert_eq!(
        from_wire_name("validatorL1Stream").unwrap().admission,
        ResolveKnownUser
    );
    assert_eq!(
        from_wire_name("SignValidatorSetUpdateAction")
            .unwrap()
            .admission,
        AnySigner
    );
    assert_eq!(
        from_wire_name("SystemSendAssetAction").unwrap().admission,
        Refused
    );
    assert_eq!(
        from_wire_name("agentSendAsset").unwrap().admission,
        ResolveKnownUser
    );
}
