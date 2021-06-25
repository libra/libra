/// Stores the string name of a ValidatorOperator account.
module DiemFramework::ValidatorOperatorConfig {
    use Std::Errors;
    use Std::Signer;
    use DiemFramework::Roles;
    use DiemFramework::DiemTimestamp;
    friend DiemFramework::DiemAccount;

    struct ValidatorOperatorConfig has key {
        /// The human readable name of this entity. Immutable.
        human_name: vector<u8>,
    }

    /// The `ValidatorOperatorConfig` was not in the required state
    const EVALIDATOR_OPERATOR_CONFIG: u64 = 0;

    public(friend) fun publish(
        validator_operator_account: &signer,
        dr_account: &signer,
        human_name: vector<u8>,
    ) {
        DiemTimestamp::assert_operating();
        Roles::assert_diem_root(dr_account);
        Roles::assert_validator_operator(validator_operator_account);
        assert(
            !has_validator_operator_config(Signer::address_of(validator_operator_account)),
            Errors::already_published(EVALIDATOR_OPERATOR_CONFIG)
        );

        move_to(validator_operator_account, ValidatorOperatorConfig {
            human_name,
        });
    }
    spec publish {
        include Roles::AbortsIfNotDiemRoot{account: dr_account};
        include Roles::AbortsIfNotValidatorOperator{validator_operator_addr: Signer::address_of(validator_operator_account)};
        include PublishAbortsIf {validator_operator_addr: Signer::spec_address_of(validator_operator_account)};
        ensures has_validator_operator_config(Signer::spec_address_of(validator_operator_account));
    }

    spec schema PublishAbortsIf {
        validator_operator_addr: address;
        dr_account: signer;
        include DiemTimestamp::AbortsIfNotOperating;
        include Roles::AbortsIfNotDiemRoot{account: dr_account};
        include Roles::AbortsIfNotValidatorOperator;
        aborts_if has_validator_operator_config(validator_operator_addr)
            with Errors::ALREADY_PUBLISHED;
    }

    /// Get validator's account human name
    /// Aborts if there is no ValidatorOperatorConfig resource
    public fun get_human_name(validator_operator_addr: address): vector<u8> acquires ValidatorOperatorConfig {
        assert(has_validator_operator_config(validator_operator_addr), Errors::not_published(EVALIDATOR_OPERATOR_CONFIG));
        *&borrow_global<ValidatorOperatorConfig>(validator_operator_addr).human_name
    }
    spec get_human_name {
        pragma opaque;
        aborts_if !has_validator_operator_config(validator_operator_addr) with Errors::NOT_PUBLISHED;
        ensures result == get_human_name(validator_operator_addr);
    }
    public fun has_validator_operator_config(validator_operator_addr: address): bool {
        exists<ValidatorOperatorConfig>(validator_operator_addr)
    }
    spec has_validator_operator_config {
        ensures result == has_validator_operator_config(validator_operator_addr);
    }

    spec module {} // switch documentation context back to module level

    /// # Consistency Between Resources and Roles

    /// If an address has a ValidatorOperatorConfig resource, it has a validator operator role.
    spec module {
        invariant forall addr: address where has_validator_operator_config(addr):
            Roles::spec_has_validator_operator_role_addr(addr);
    }

    /// # Persistence
    spec module {
        invariant update forall addr: address where old(exists<ValidatorOperatorConfig>(addr)):
            exists<ValidatorOperatorConfig>(addr);
    }

}
