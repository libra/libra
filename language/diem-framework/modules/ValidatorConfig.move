/// The ValidatorConfig resource holds information about a validator. Information
/// is published and updated by Diem root in a `Self::ValidatorConfig` in preparation for
/// later inclusion (by functions in DiemConfig) in a `DiemConfig::DiemConfig<DiemSystem>`
/// struct (the `Self::ValidatorConfig` in a `DiemConfig::ValidatorInfo` which is a member
/// of the `DiemSystem::DiemSystem.validators` vector).
module DiemFramework::ValidatorConfig {
    use DiemFramework::DiemTimestamp;
    use Std::Errors;
    use DiemFramework::Signature;
    use DiemFramework::Roles;
    use DiemFramework::ValidatorOperatorConfig;
    use Std::Option::{Self, Option};
    use Std::Signer;
    friend DiemFramework::DiemAccount;

    struct Config has copy, drop, store {
        consensus_pubkey: vector<u8>,
        validator_network_addresses: vector<u8>,
        fullnode_network_addresses: vector<u8>,
    }

    struct ValidatorConfig has key {
        /// set and rotated by the operator_account
        config: Option<Config>,
        operator_account: Option<address>,
        /// The human readable name of this entity. Immutable.
        human_name: vector<u8>,
    }

    // TODO(valerini): add events here

    /// The `ValidatorConfig` resource was not in the required state
    const EVALIDATOR_CONFIG: u64 = 0;
    /// The sender is not the operator for the specified validator
    const EINVALID_TRANSACTION_SENDER: u64 = 1;
    /// The provided consensus public key is malformed
    const EINVALID_CONSENSUS_KEY: u64 = 2;
    /// Tried to set an account without the correct operator role as a Validator Operator
    const ENOT_A_VALIDATOR_OPERATOR: u64 = 3;

    ///////////////////////////////////////////////////////////////////////////
    // Validator setup methods
    ///////////////////////////////////////////////////////////////////////////

    /// Publishes a mostly empty ValidatorConfig struct. Eventually, it
    /// will have critical info such as keys, network addresses for validators,
    /// and the address of the validator operator.
    public(friend) fun publish(
        validator_account: &signer,
        dr_account: &signer,
        human_name: vector<u8>,
    ) {
        DiemTimestamp::assert_operating();
        Roles::assert_diem_root(dr_account);
        Roles::assert_validator(validator_account);
        assert(
            !exists<ValidatorConfig>(Signer::address_of(validator_account)),
            Errors::already_published(EVALIDATOR_CONFIG)
        );
        move_to(validator_account, ValidatorConfig {
            config: Option::none(),
            operator_account: Option::none(),
            human_name,
        });
    }

    spec publish {
        include PublishAbortsIf {validator_addr: Signer::spec_address_of(validator_account)};
        ensures exists_config(Signer::spec_address_of(validator_account));
    }

    spec schema PublishAbortsIf {
        validator_addr: address;
        dr_account: signer;
        include DiemTimestamp::AbortsIfNotOperating;
        include Roles::AbortsIfNotDiemRoot{account: dr_account};
        include Roles::AbortsIfNotValidator{validator_addr: validator_addr};
        aborts_if exists_config(validator_addr)
            with Errors::ALREADY_PUBLISHED;
    }

    /// Returns true if a ValidatorConfig resource exists under addr.
    fun exists_config(addr: address): bool {
        exists<ValidatorConfig>(addr)
    }

    /// Describes abort if ValidatorConfig does not exist.
    spec schema AbortsIfNoValidatorConfig {
        addr: address;
        aborts_if !exists_config(addr) with Errors::NOT_PUBLISHED;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Rotation methods callable by ValidatorConfig owner
    ///////////////////////////////////////////////////////////////////////////

    /// Sets a new operator account, preserving the old config.
    /// Note: Access control.  No one but the owner of the account may change .operator_account
    public fun set_operator(validator_account: &signer, operator_addr: address) acquires ValidatorConfig {
        Roles::assert_validator(validator_account);
        // Check for validator role is not necessary since the role is checked when the config
        // resource is published.
        assert(
            ValidatorOperatorConfig::has_validator_operator_config(operator_addr),
            Errors::invalid_argument(ENOT_A_VALIDATOR_OPERATOR)
        );
        let sender = Signer::address_of(validator_account);
        assert(exists_config(sender), Errors::not_published(EVALIDATOR_CONFIG));
        (borrow_global_mut<ValidatorConfig>(sender)).operator_account = Option::some(operator_addr);
    }
    spec set_operator {
        /// Must abort if the signer does not have the Validator role [[H16]][PERMISSION].
        let sender = Signer::spec_address_of(validator_account);
        include Roles::AbortsIfNotValidator{validator_addr: sender};
        include SetOperatorAbortsIf;
        include SetOperatorEnsures;
    }

    spec schema SetOperatorAbortsIf {
        /// Must abort if the signer does not have the Validator role [B24].
        validator_account: signer;
        operator_addr: address;
        let validator_addr = Signer::spec_address_of(validator_account);
        include Roles::AbortsIfNotValidator{validator_addr: validator_addr};
        aborts_if !ValidatorOperatorConfig::has_validator_operator_config(operator_addr)
            with Errors::INVALID_ARGUMENT;
        include AbortsIfNoValidatorConfig{addr: validator_addr};
        aborts_if !ValidatorOperatorConfig::has_validator_operator_config(operator_addr) with Errors::NOT_PUBLISHED;
    }

    spec schema SetOperatorEnsures {
        validator_account: signer;
        operator_addr: address;
        let validator_addr = Signer::spec_address_of(validator_account);
        ensures spec_has_operator(validator_addr);
        ensures get_operator(validator_addr) == operator_addr;
        /// The signer can only change its own operator account [[H16]][PERMISSION].
        ensures forall addr: address where addr != validator_addr:
            global<ValidatorConfig>(addr).operator_account == old(global<ValidatorConfig>(addr).operator_account);
    }

    /// Removes an operator account, setting a corresponding field to Option::none.
    /// The old config is preserved.
    public fun remove_operator(validator_account: &signer) acquires ValidatorConfig {
        Roles::assert_validator(validator_account);
        let sender = Signer::address_of(validator_account);
        // Config field remains set
        assert(exists_config(sender), Errors::not_published(EVALIDATOR_CONFIG));
        (borrow_global_mut<ValidatorConfig>(sender)).operator_account = Option::none();
    }

    spec remove_operator {
        /// Must abort if the signer does not have the Validator role [[H16]][PERMISSION].
        let sender = Signer::spec_address_of(validator_account);
        include Roles::AbortsIfNotValidator{validator_addr: sender};
        include AbortsIfNoValidatorConfig{addr: sender};
        ensures !spec_has_operator(Signer::spec_address_of(validator_account));

        /// The signer can only change its own operator account [[H16]][PERMISSION].
        ensures forall addr: address where addr != sender:
            global<ValidatorConfig>(addr).operator_account == old(global<ValidatorConfig>(addr).operator_account);
    }

    ///////////////////////////////////////////////////////////////////////////
    // Rotation methods callable by ValidatorConfig.operator_account
    ///////////////////////////////////////////////////////////////////////////

    /// Rotate the config in the validator_account.
    /// Once the config is set, it can not go back to `Option::none` - this is crucial for validity
    /// of the DiemSystem's code.
    public fun set_config(
        validator_operator_account: &signer,
        validator_addr: address,
        consensus_pubkey: vector<u8>,
        validator_network_addresses: vector<u8>,
        fullnode_network_addresses: vector<u8>,
    ) acquires ValidatorConfig {
        assert(
            Signer::address_of(validator_operator_account) == get_operator(validator_addr),
            Errors::invalid_argument(EINVALID_TRANSACTION_SENDER)
        );
        assert(
            Signature::ed25519_validate_pubkey(copy consensus_pubkey),
            Errors::invalid_argument(EINVALID_CONSENSUS_KEY)
        );
        // TODO(valerini): verify the proof of posession for consensus_pubkey
        assert(exists_config(validator_addr), Errors::not_published(EVALIDATOR_CONFIG));
        let t_ref = borrow_global_mut<ValidatorConfig>(validator_addr);
        t_ref.config = Option::some(Config {
            consensus_pubkey,
            validator_network_addresses,
            fullnode_network_addresses,
        });
    }
    spec set_config {
        pragma opaque;
        modifies global<ValidatorConfig>(validator_addr);
        include SetConfigAbortsIf;
        ensures is_valid(validator_addr);
        ensures global<ValidatorConfig>(validator_addr)
                == update_field(old(global<ValidatorConfig>(validator_addr)),
                                config,
                                Option::spec_some(Config {
                                                 consensus_pubkey,
                                                 validator_network_addresses,
                                                 fullnode_network_addresses,
                                             }));
    }
    spec schema SetConfigAbortsIf {
        validator_operator_account: signer;
        validator_addr: address;
        consensus_pubkey: vector<u8>;
        aborts_if Signer::address_of(validator_operator_account) != get_operator(validator_addr)
            with Errors::INVALID_ARGUMENT;
        include AbortsIfGetOperator{addr: validator_addr};
        aborts_if !Signature::ed25519_validate_pubkey(consensus_pubkey) with Errors::INVALID_ARGUMENT;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Publicly callable APIs: getters
    ///////////////////////////////////////////////////////////////////////////

    /// Returns true if all of the following is true:
    /// 1) there is a ValidatorConfig resource under the address, and
    /// 2) the config is set, and
    /// we do not require the operator_account to be set to make sure
    /// that if the validator account becomes valid, it stays valid, e.g.
    /// all validators in the Validator Set are valid
    public fun is_valid(addr: address): bool acquires ValidatorConfig {
        exists<ValidatorConfig>(addr) && Option::is_some(&borrow_global<ValidatorConfig>(addr).config)
    }

    spec is_valid {
        pragma opaque;
        aborts_if false;
        ensures result == is_valid(addr);
    }

    /// Get Config
    /// Aborts if there is no ValidatorConfig resource or if its config is empty
    public fun get_config(addr: address): Config acquires ValidatorConfig {
        assert(exists_config(addr), Errors::not_published(EVALIDATOR_CONFIG));
        let config = &borrow_global<ValidatorConfig>(addr).config;
        assert(Option::is_some(config), Errors::invalid_argument(EVALIDATOR_CONFIG));
        *Option::borrow(config)
    }

    spec get_config {
        pragma opaque;
        include AbortsIfNoValidatorConfig;
        aborts_if Option::is_none(global<ValidatorConfig>(addr).config) with Errors::INVALID_ARGUMENT;
        ensures result == spec_get_config(addr);
    }

    /// Returns the config published under addr.
    spec fun spec_get_config(addr: address): Config {
        Option::borrow(global<ValidatorConfig>(addr).config)
    }

    /// Get validator's account human name
    /// Aborts if there is no ValidatorConfig resource
    public fun get_human_name(addr: address): vector<u8> acquires ValidatorConfig {
        assert(exists<ValidatorConfig>(addr), Errors::not_published(EVALIDATOR_CONFIG));
        let t_ref = borrow_global<ValidatorConfig>(addr);
        *&t_ref.human_name
    }

    spec get_human_name {
        pragma opaque;
        include AbortsIfNoValidatorConfig;
        ensures result == get_human_name(addr);
    }

    /// Get operator's account
    /// Aborts if there is no ValidatorConfig resource or
    /// if the operator_account is unset
    public fun get_operator(addr: address): address acquires ValidatorConfig {
        assert(exists<ValidatorConfig>(addr), Errors::not_published(EVALIDATOR_CONFIG));
        let t_ref = borrow_global<ValidatorConfig>(addr);
        assert(Option::is_some(&t_ref.operator_account), Errors::invalid_argument(EVALIDATOR_CONFIG));
        *Option::borrow(&t_ref.operator_account)
    }

    spec get_operator {
        pragma opaque;
        include AbortsIfGetOperator;
        ensures result == get_operator(addr);
    }

    spec schema AbortsIfGetOperator {
        addr: address;
        include AbortsIfNoValidatorConfig;
        aborts_if !spec_has_operator(addr) with Errors::INVALID_ARGUMENT;
    }

    /// Get consensus_pubkey from Config
    /// Never aborts
    public fun get_consensus_pubkey(config_ref: &Config): &vector<u8> {
        &config_ref.consensus_pubkey
    }

    /// Get validator's network address from Config
    /// Never aborts
    public fun get_validator_network_addresses(config_ref: &Config): &vector<u8> {
        &config_ref.validator_network_addresses
    }

    spec module {} // Switch documentation context to module level.

    spec module {
        pragma aborts_if_is_strict;
    }

    /// # Access Control

    spec module {
        /// Only `Self::set_operator` and `Self::remove_operator` may change the operator for a
        /// particular (validator owner) address [[H16]][PERMISSION].
        /// These two functions have a &signer argument for the validator account, so we know
        /// that the change has been authorized by the validator owner via signing the transaction.
        apply OperatorRemainsSame to * except set_operator, remove_operator;
    }

    spec schema OperatorRemainsSame {
        ensures forall addr1: address where old(exists<ValidatorConfig>(addr1)):
            global<ValidatorConfig>(addr1).operator_account == old(global<ValidatorConfig>(addr1).operator_account);
    }

    /// # Validity of Validators

    /// See comment on `ValidatorConfig::set_config` -- DiemSystem depends on this.
    spec module {
        /// A validator stays valid once it becomes valid.
        invariant update
            forall validator: address where old(is_valid(validator)): is_valid(validator);
    }

    /// # Consistency Between Resources and Roles

    spec module {

        /// Every address that has a ValidatorConfig also has a validator role.
        invariant forall addr: address where exists_config(addr):
            Roles::spec_has_validator_role_addr(addr);

        /// DIP-6 Property: If address has a ValidatorConfig, it has a validator role.  This invariant is useful
        /// in DiemSystem so we don't have to check whether every validator address has a validator role.
        invariant forall addr: address where exists_config(addr):
            Roles::spec_has_validator_role_addr(addr);

        /// DIP-6 Property: Every address that is_valid (meaning it has a ValidatorConfig with
        /// a config option that is "some") has a validator role. This is a trivial consequence
        /// of the previous invariant, but it is not inductive and can't be proved without the
        /// previous one as a helper.
        invariant forall addr: address where is_valid(addr):
            Roles::spec_has_validator_role_addr(addr);
    }

    /// # Helper Function

    /// Returns true if addr has an operator account.
    spec fun spec_has_operator(addr: address): bool {
        Option::is_some(global<ValidatorConfig>(addr).operator_account)
    }
}
