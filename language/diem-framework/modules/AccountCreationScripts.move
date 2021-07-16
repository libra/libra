module DiemFramework::AccountCreationScripts {
    use DiemFramework::DiemAccount;
    use DiemFramework::SlidingNonce;

    /// # Summary
    /// Creates a Child VASP account with its parent being the sending account of the transaction.
    /// The sender of the transaction must be a Parent VASP account.
    ///
    /// # Technical Description
    /// Creates a `ChildVASP` account for the sender `parent_vasp` at `child_address` with a balance of
    /// `child_initial_balance` in `CoinType` and an initial authentication key of
    /// `auth_key_prefix | child_address`. Authentication key prefixes, and how to construct them from an ed25519 public key is described
    /// [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).
    ///
    /// If `add_all_currencies` is true, the child address will have a zero balance in all available
    /// currencies in the system.
    ///
    /// The new account will be a child account of the transaction sender, which must be a
    /// Parent VASP account. The child account will be recorded against the limit of
    /// child accounts of the creating Parent VASP account.
    ///
    /// # Events
    /// Successful execution will emit:
    /// * A `DiemAccount::CreateAccountEvent` with the `created` field being `child_address`,
    /// and the `rold_id` field being `Roles::CHILD_VASP_ROLE_ID`. This is emitted on the
    /// `DiemAccount::AccountOperationsCapability` `creation_events` handle.
    ///
    /// Successful execution with a `child_initial_balance` greater than zero will additionaly emit:
    /// * A `DiemAccount::SentPaymentEvent` with the `payee` field being `child_address`.
    /// This is emitted on the Parent VASP's `DiemAccount::DiemAccount` `sent_events` handle.
    /// * A `DiemAccount::ReceivedPaymentEvent` with the  `payer` field being the Parent VASP's address.
    /// This is emitted on the new Child VASPS's `DiemAccount::DiemAccount` `received_events` handle.
    ///
    /// # Parameters
    /// | Name                    | Type         | Description                                                                                                                                 |
    /// | ------                  | ------       | -------------                                                                                                                               |
    /// | `CoinType`              | Type         | The Move type for the `CoinType` that the child account should be created with. `CoinType` must be an already-registered currency on-chain. |
    /// | `parent_vasp`           | `signer`     | The reference of the sending account. Must be a Parent VASP account.                                                                        |
    /// | `child_address`         | `address`    | Address of the to-be-created Child VASP account.                                                                                            |
    /// | `auth_key_prefix`       | `vector<u8>` | The authentication key prefix that will be used initially for the newly created account.                                                    |
    /// | `add_all_currencies`    | `bool`       | Whether to publish balance resources for all known currencies when the account is created.                                                  |
    /// | `child_initial_balance` | `u64`        | The initial balance in `CoinType` to give the child account when it's created.                                                              |
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason                                             | Description                                                                              |
    /// | ----------------            | --------------                                           | -------------                                                                            |
    /// | `Errors::INVALID_ARGUMENT`  | `DiemAccount::EMALFORMED_AUTHENTICATION_KEY`            | The `auth_key_prefix` was not of length 32.                                              |
    /// | `Errors::REQUIRES_ROLE`     | `Roles::EPARENT_VASP`                                    | The sending account wasn't a Parent VASP account.                                        |
    /// | `Errors::ALREADY_PUBLISHED` | `Roles::EROLE_ID`                                        | The `child_address` address is already taken.                                            |
    /// | `Errors::LIMIT_EXCEEDED`    | `VASP::ETOO_MANY_CHILDREN`                               | The sending account has reached the maximum number of allowed child accounts.            |
    /// | `Errors::NOT_PUBLISHED`     | `Diem::ECURRENCY_INFO`                                  | The `CoinType` is not a registered currency on-chain.                                    |
    /// | `Errors::INVALID_STATE`     | `DiemAccount::EWITHDRAWAL_CAPABILITY_ALREADY_EXTRACTED` | The withdrawal capability for the sending account has already been extracted.            |
    /// | `Errors::NOT_PUBLISHED`     | `DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY`              | The sending account doesn't have a balance in `CoinType`.                                |
    /// | `Errors::LIMIT_EXCEEDED`    | `DiemAccount::EINSUFFICIENT_BALANCE`                    | The sending account doesn't have at least `child_initial_balance` of `CoinType` balance. |
    /// | `Errors::INVALID_ARGUMENT`  | `DiemAccount::ECANNOT_CREATE_AT_VM_RESERVED`            | The `child_address` is the reserved address 0x0.                                         |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_parent_vasp_account`
    /// * `AccountAdministrationScripts::add_currency_to_account`
    /// * `AccountAdministrationScripts::rotate_authentication_key`
    /// * `AccountAdministrationScripts::add_recovery_rotation_capability`
    /// * `AccountAdministrationScripts::create_recovery_address`

    public(script) fun create_child_vasp_account<CoinType>(
        parent_vasp: signer,
        child_address: address,
        auth_key_prefix: vector<u8>,
        add_all_currencies: bool,
        child_initial_balance: u64
    ) {
        DiemAccount::create_child_vasp_account<CoinType>(
            &parent_vasp,
            child_address,
            auth_key_prefix,
            add_all_currencies,
        );
        // Give the newly created child `child_initial_balance` coins
        if (child_initial_balance > 0) {
            let vasp_withdrawal_cap = DiemAccount::extract_withdraw_capability(&parent_vasp);
            DiemAccount::pay_from<CoinType>(
                &vasp_withdrawal_cap, child_address, child_initial_balance, x"", x""
            );
            DiemAccount::restore_withdraw_capability(vasp_withdrawal_cap);
        };
    }

    spec create_child_vasp_account {
        use Std::Signer;
        use Std::Errors;
        use DiemFramework::DualAttestation;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: parent_vasp}; // properties checked by the prologue.
        let parent_addr = Signer::spec_address_of(parent_vasp);
        let parent_cap = DiemAccount::spec_get_withdraw_cap(parent_addr);
        include DiemAccount::CreateChildVASPAccountAbortsIf<CoinType>{
            parent: parent_vasp, new_account_address: child_address};
        aborts_if child_initial_balance > max_u64() with Errors::LIMIT_EXCEEDED;
        include (child_initial_balance > 0) ==>
            DiemAccount::ExtractWithdrawCapAbortsIf{sender_addr: parent_addr};
        include (child_initial_balance > 0) ==> DualAttestation::AssertPaymentOkAbortsIf<CoinType>{
            payer: parent_addr,
            payee: child_address,
            metadata: x"",
            metadata_signature: x"",
            value: child_initial_balance
        };
        include (child_initial_balance) > 0 ==>
            DiemAccount::PayFromAbortsIfRestricted<CoinType>{
                cap: parent_cap,
                payee: child_address,
                amount: child_initial_balance,
                metadata: x"",
            };
        include DiemAccount::CreateChildVASPAccountEnsures<CoinType>{
            parent_addr: parent_addr,
            child_addr: child_address,
        };
        ensures DiemAccount::balance<CoinType>(child_address) == child_initial_balance;
        ensures DiemAccount::balance<CoinType>(parent_addr)
            == old(DiemAccount::balance<CoinType>(parent_addr)) - child_initial_balance;

        aborts_with [check]
            Errors::REQUIRES_ROLE,
            Errors::ALREADY_PUBLISHED,
            Errors::LIMIT_EXCEEDED,
            Errors::NOT_PUBLISHED,
            Errors::INVALID_STATE,
            Errors::INVALID_ARGUMENT;

        // TODO: fix emit specs below
        /*
        include DiemAccount::MakeAccountEmits{new_account_address: child_address};
        include child_initial_balance > 0 ==>
            DiemAccount::PayFromEmits<CoinType>{
                cap: parent_cap,
                payee: child_address,
                amount: child_initial_balance,
                metadata: x"",
            };
        */

        /// **Access Control:**
        /// Only Parent VASP accounts can create Child VASP accounts [[A7]][ROLE].
        include Roles::AbortsIfNotParentVasp{account: parent_vasp};
    }

    /// # Summary
    /// Creates a Validator Operator account. This transaction can only be sent by the Diem
    /// Root account.
    ///
    /// # Technical Description
    /// Creates an account with a Validator Operator role at `new_account_address`, with authentication key
    /// `auth_key_prefix` | `new_account_address`. It publishes a
    /// `ValidatorOperatorConfig::ValidatorOperatorConfig` resource with the specified `human_name`.
    /// This script does not assign the validator operator to any validator accounts but only creates the account.
    /// Authentication key prefixes, and how to construct them from an ed25519 public key are described
    /// [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).
    ///
    /// # Events
    /// Successful execution will emit:
    /// * A `DiemAccount::CreateAccountEvent` with the `created` field being `new_account_address`,
    /// and the `rold_id` field being `Roles::VALIDATOR_OPERATOR_ROLE_ID`. This is emitted on the
    /// `DiemAccount::AccountOperationsCapability` `creation_events` handle.
    ///
    /// # Parameters
    /// | Name                  | Type         | Description                                                                              |
    /// | ------                | ------       | -------------                                                                            |
    /// | `dr_account`          | `signer`     | The signer of the sending account of this transaction. Must be the Diem Root signer.     |
    /// | `sliding_nonce`       | `u64`        | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.               |
    /// | `new_account_address` | `address`    | Address of the to-be-created Validator account.                                          |
    /// | `auth_key_prefix`     | `vector<u8>` | The authentication key prefix that will be used initially for the newly created account. |
    /// | `human_name`          | `vector<u8>` | ASCII-encoded human name for the validator.                                              |
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason                            | Description                                                                                |
    /// | ----------------            | --------------                          | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`     | `SlidingNonce::ESLIDING_NONCE`          | A `SlidingNonce` resource is not published under `dr_account`.                             |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_TOO_OLD`          | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_TOO_NEW`          | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_ALREADY_RECORDED` | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::REQUIRES_ADDRESS`  | `CoreAddresses::EDIEM_ROOT`            | The sending account is not the Diem Root account.                                         |
    /// | `Errors::REQUIRES_ROLE`     | `Roles::EDIEM_ROOT`                    | The sending account is not the Diem Root account.                                         |
    /// | `Errors::ALREADY_PUBLISHED` | `Roles::EROLE_ID`                       | The `new_account_address` address is already taken.                                        |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_validator_account`
    /// * `ValidatorAdministrationScripts::add_validator_and_reconfigure`
    /// * `ValidatorAdministrationScripts::register_validator_config`
    /// * `ValidatorAdministrationScripts::remove_validator_and_reconfigure`
    /// * `ValidatorAdministrationScripts::set_validator_operator`
    /// * `ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin`
    /// * `ValidatorAdministrationScripts::set_validator_config_and_reconfigure`

    public(script) fun create_validator_operator_account(
        dr_account: signer,
        sliding_nonce: u64,
        new_account_address: address,
        auth_key_prefix: vector<u8>,
        human_name: vector<u8>
    ) {
        SlidingNonce::record_nonce_or_abort(&dr_account, sliding_nonce);
        DiemAccount::create_validator_operator_account(
            &dr_account,
            new_account_address,
            auth_key_prefix,
            human_name,
        );
    }

    /// Only Diem root may create Validator Operator accounts
    /// Authentication: ValidatorAccountAbortsIf includes AbortsIfNotDiemRoot.
    /// Checks that above table includes all error categories.
    /// The verifier finds an abort that is not documented, and cannot occur in practice:
    /// * REQUIRES_ROLE comes from `Roles::assert_diem_root`. However, assert_diem_root checks the literal
    ///   Diem root address before checking the role, and the role abort is unreachable in practice, since
    ///   only Diem root has the Diem root role.
    spec create_validator_operator_account {
        use Std::Errors;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: dr_account}; // properties checked by the prologue.
        include SlidingNonce::RecordNonceAbortsIf{seq_nonce: sliding_nonce, account: dr_account};
        include DiemAccount::CreateValidatorOperatorAccountAbortsIf;
        include DiemAccount::CreateValidatorOperatorAccountEnsures;

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::NOT_PUBLISHED,
            Errors::REQUIRES_ADDRESS,
            Errors::ALREADY_PUBLISHED,
            Errors::REQUIRES_ROLE;

        include DiemAccount::MakeAccountEmits;

        /// **Access Control:**
        /// Only the Diem Root account can create Validator Operator accounts [[A4]][ROLE].
        include Roles::AbortsIfNotDiemRoot{account: dr_account};
    }

    /// # Summary
    /// Creates a Validator account. This transaction can only be sent by the Diem
    /// Root account.
    ///
    /// # Technical Description
    /// Creates an account with a Validator role at `new_account_address`, with authentication key
    /// `auth_key_prefix` | `new_account_address`. It publishes a
    /// `ValidatorConfig::ValidatorConfig` resource with empty `config`, and
    /// `operator_account` fields. The `human_name` field of the
    /// `ValidatorConfig::ValidatorConfig` is set to the passed in `human_name`.
    /// This script does not add the validator to the validator set or the system,
    /// but only creates the account.
    /// Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
    /// [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).
    ///
    /// # Events
    /// Successful execution will emit:
    /// * A `DiemAccount::CreateAccountEvent` with the `created` field being `new_account_address`,
    /// and the `rold_id` field being `Roles::VALIDATOR_ROLE_ID`. This is emitted on the
    /// `DiemAccount::AccountOperationsCapability` `creation_events` handle.
    ///
    /// # Parameters
    /// | Name                  | Type         | Description                                                                              |
    /// | ------                | ------       | -------------                                                                            |
    /// | `dr_account`          | `signer`     | The signer of the sending account of this transaction. Must be the Diem Root signer.     |
    /// | `sliding_nonce`       | `u64`        | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.               |
    /// | `new_account_address` | `address`    | Address of the to-be-created Validator account.                                          |
    /// | `auth_key_prefix`     | `vector<u8>` | The authentication key prefix that will be used initially for the newly created account. |
    /// | `human_name`          | `vector<u8>` | ASCII-encoded human name for the validator.                                              |
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason                            | Description                                                                                |
    /// | ----------------            | --------------                          | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`     | `SlidingNonce::ESLIDING_NONCE`          | A `SlidingNonce` resource is not published under `dr_account`.                             |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_TOO_OLD`          | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_TOO_NEW`          | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_ALREADY_RECORDED` | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::REQUIRES_ADDRESS`  | `CoreAddresses::EDIEM_ROOT`            | The sending account is not the Diem Root account.                                         |
    /// | `Errors::REQUIRES_ROLE`     | `Roles::EDIEM_ROOT`                    | The sending account is not the Diem Root account.                                         |
    /// | `Errors::ALREADY_PUBLISHED` | `Roles::EROLE_ID`                       | The `new_account_address` address is already taken.                                        |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_validator_operator_account`
    /// * `ValidatorAdministrationScripts::add_validator_and_reconfigure`
    /// * `ValidatorAdministrationScripts::register_validator_config`
    /// * `ValidatorAdministrationScripts::remove_validator_and_reconfigure`
    /// * `ValidatorAdministrationScripts::set_validator_operator`
    /// * `ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin`
    /// * `ValidatorAdministrationScripts::set_validator_config_and_reconfigure`

    public(script) fun create_validator_account(
        dr_account: signer,
        sliding_nonce: u64,
        new_account_address: address,
        auth_key_prefix: vector<u8>,
        human_name: vector<u8>,
    ) {
        SlidingNonce::record_nonce_or_abort(&dr_account, sliding_nonce);
        DiemAccount::create_validator_account(
            &dr_account,
            new_account_address,
            auth_key_prefix,
            human_name,
        );
      }

    /// Only Diem root may create Validator accounts
    /// Authentication: ValidatorAccountAbortsIf includes AbortsIfNotDiemRoot.
    /// Checks that above table includes all error categories.
    /// The verifier finds an abort that is not documented, and cannot occur in practice:
    /// * REQUIRES_ROLE comes from `Roles::assert_diem_root`. However, assert_diem_root checks the literal
    ///   Diem root address before checking the role, and the role abort is unreachable in practice, since
    ///   only Diem root has the Diem root role.
    spec create_validator_account {
        use Std::Errors;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: dr_account}; // properties checked by the prologue.
        include SlidingNonce::RecordNonceAbortsIf{seq_nonce: sliding_nonce, account: dr_account};
        include DiemAccount::CreateValidatorAccountAbortsIf;
        include DiemAccount::CreateValidatorAccountEnsures;

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::NOT_PUBLISHED,
            Errors::REQUIRES_ADDRESS,
            Errors::ALREADY_PUBLISHED,
            Errors::REQUIRES_ROLE;

        include DiemAccount::MakeAccountEmits;

        /// **Access Control:**
        /// Only the Diem Root account can create Validator accounts [[A3]][ROLE].
        include Roles::AbortsIfNotDiemRoot{account: dr_account};
    }

    /// # Summary
    /// Creates a Parent VASP account with the specified human name. Must be called by the Treasury Compliance account.
    ///
    /// # Technical Description
    /// Creates an account with the Parent VASP role at `address` with authentication key
    /// `auth_key_prefix` | `new_account_address` and a 0 balance of type `CoinType`. If
    /// `add_all_currencies` is true, 0 balances for all available currencies in the system will
    /// also be added. This can only be invoked by an TreasuryCompliance account.
    /// `sliding_nonce` is a unique nonce for operation, see `SlidingNonce` for details.
    /// Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
    /// [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).
    ///
    /// # Events
    /// Successful execution will emit:
    /// * A `DiemAccount::CreateAccountEvent` with the `created` field being `new_account_address`,
    /// and the `rold_id` field being `Roles::PARENT_VASP_ROLE_ID`. This is emitted on the
    /// `DiemAccount::AccountOperationsCapability` `creation_events` handle.
    ///
    /// # Parameters
    /// | Name                  | Type         | Description                                                                                                                                                    |
    /// | ------                | ------       | -------------                                                                                                                                                  |
    /// | `CoinType`            | Type         | The Move type for the `CoinType` currency that the Parent VASP account should be initialized with. `CoinType` must be an already-registered currency on-chain. |
    /// | `tc_account`          | `signer`     | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                                |
    /// | `sliding_nonce`       | `u64`        | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.                                                                                     |
    /// | `new_account_address` | `address`    | Address of the to-be-created Parent VASP account.                                                                                                              |
    /// | `auth_key_prefix`     | `vector<u8>` | The authentication key prefix that will be used initially for the newly created account.                                                                       |
    /// | `human_name`          | `vector<u8>` | ASCII-encoded human name for the Parent VASP.                                                                                                                  |
    /// | `add_all_currencies`  | `bool`       | Whether to publish balance resources for all known currencies when the account is created.                                                                     |
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason                            | Description                                                                                |
    /// | ----------------            | --------------                          | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`     | `SlidingNonce::ESLIDING_NONCE`          | A `SlidingNonce` resource is not published under `tc_account`.                             |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_TOO_OLD`          | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_TOO_NEW`          | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_ALREADY_RECORDED` | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::REQUIRES_ADDRESS`  | `CoreAddresses::ETREASURY_COMPLIANCE`   | The sending account is not the Treasury Compliance account.                                |
    /// | `Errors::REQUIRES_ROLE`     | `Roles::ETREASURY_COMPLIANCE`           | The sending account is not the Treasury Compliance account.                                |
    /// | `Errors::NOT_PUBLISHED`     | `Diem::ECURRENCY_INFO`                 | The `CoinType` is not a registered currency on-chain.                                      |
    /// | `Errors::ALREADY_PUBLISHED` | `Roles::EROLE_ID`                       | The `new_account_address` address is already taken.                                        |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_child_vasp_account`
    /// * `AccountAdministrationScripts::add_currency_to_account`
    /// * `AccountAdministrationScripts::rotate_authentication_key`
    /// * `AccountAdministrationScripts::add_recovery_rotation_capability`
    /// * `AccountAdministrationScripts::create_recovery_address`
    /// * `AccountAdministrationScripts::rotate_dual_attestation_info`

    public(script) fun create_parent_vasp_account<CoinType>(
        tc_account: signer,
        sliding_nonce: u64,
        new_account_address: address,
        auth_key_prefix: vector<u8>,
        human_name: vector<u8>,
        add_all_currencies: bool
    ) {
        SlidingNonce::record_nonce_or_abort(&tc_account, sliding_nonce);
        DiemAccount::create_parent_vasp_account<CoinType>(
            &tc_account,
            new_account_address,
            auth_key_prefix,
            human_name,
            add_all_currencies
        );
    }

    spec create_parent_vasp_account {
        use Std::Errors;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: tc_account}; // properties checked by the prologue.
        include SlidingNonce::RecordNonceAbortsIf{account: tc_account, seq_nonce: sliding_nonce};
        include DiemAccount::CreateParentVASPAccountAbortsIf<CoinType>{creator_account: tc_account};
        include DiemAccount::CreateParentVASPAccountEnsures<CoinType>;

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::REQUIRES_ADDRESS,
            Errors::NOT_PUBLISHED,
            Errors::ALREADY_PUBLISHED,
            Errors::REQUIRES_ROLE;

        include DiemAccount::MakeAccountEmits;

        /// **Access Control:**
        /// Only the Treasury Compliance account can create Parent VASP accounts [[A6]][ROLE].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
    }

    /// # Summary
    /// Creates a Designated Dealer account with the provided information, and initializes it with
    /// default mint tiers. The transaction can only be sent by the Treasury Compliance account.
    ///
    /// # Technical Description
    /// Creates an account with the Designated Dealer role at `addr` with authentication key
    /// `auth_key_prefix` | `addr` and a 0 balance of type `Currency`. If `add_all_currencies` is true,
    /// 0 balances for all available currencies in the system will also be added. This can only be
    /// invoked by an account with the TreasuryCompliance role.
    /// Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
    /// [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).
    ///
    /// At the time of creation the account is also initialized with default mint tiers of (500_000,
    /// 5000_000, 50_000_000, 500_000_000), and preburn areas for each currency that is added to the
    /// account.
    ///
    /// # Events
    /// Successful execution will emit:
    /// * A `DiemAccount::CreateAccountEvent` with the `created` field being `addr`,
    /// and the `rold_id` field being `Roles::DESIGNATED_DEALER_ROLE_ID`. This is emitted on the
    /// `DiemAccount::AccountOperationsCapability` `creation_events` handle.
    ///
    /// # Parameters
    /// | Name                 | Type         | Description                                                                                                                                         |
    /// | ------               | ------       | -------------                                                                                                                                       |
    /// | `Currency`           | Type         | The Move type for the `Currency` that the Designated Dealer should be initialized with. `Currency` must be an already-registered currency on-chain. |
    /// | `tc_account`         | `signer`     | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                     |
    /// | `sliding_nonce`      | `u64`        | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.                                                                          |
    /// | `addr`               | `address`    | Address of the to-be-created Designated Dealer account.                                                                                             |
    /// | `auth_key_prefix`    | `vector<u8>` | The authentication key prefix that will be used initially for the newly created account.                                                            |
    /// | `human_name`         | `vector<u8>` | ASCII-encoded human name for the Designated Dealer.                                                                                                 |
    /// | `add_all_currencies` | `bool`       | Whether to publish preburn, balance, and tier info resources for all known (SCS) currencies or just `Currency` when the account is created.         |
    ///
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason                            | Description                                                                                |
    /// | ----------------            | --------------                          | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`     | `SlidingNonce::ESLIDING_NONCE`          | A `SlidingNonce` resource is not published under `tc_account`.                             |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_TOO_OLD`          | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_TOO_NEW`          | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT`  | `SlidingNonce::ENONCE_ALREADY_RECORDED` | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::REQUIRES_ADDRESS`  | `CoreAddresses::ETREASURY_COMPLIANCE`   | The sending account is not the Treasury Compliance account.                                |
    /// | `Errors::REQUIRES_ROLE`     | `Roles::ETREASURY_COMPLIANCE`           | The sending account is not the Treasury Compliance account.                                |
    /// | `Errors::NOT_PUBLISHED`     | `Diem::ECURRENCY_INFO`                 | The `Currency` is not a registered currency on-chain.                                      |
    /// | `Errors::ALREADY_PUBLISHED` | `Roles::EROLE_ID`                       | The `addr` address is already taken.                                                       |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::tiered_mint`
    /// * `PaymentScripts::peer_to_peer_with_metadata`
    /// * `AccountAdministrationScripts::rotate_dual_attestation_info`

    public(script) fun create_designated_dealer<Currency>(
        tc_account: signer,
        sliding_nonce: u64,
        addr: address,
        auth_key_prefix: vector<u8>,
        human_name: vector<u8>,
        add_all_currencies: bool,
    ) {
        SlidingNonce::record_nonce_or_abort(&tc_account, sliding_nonce);
        DiemAccount::create_designated_dealer<Currency>(
            &tc_account,
            addr,
            auth_key_prefix,
            human_name,
            add_all_currencies
        );
    }

    spec create_designated_dealer {
        use Std::Errors;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: tc_account}; // properties checked by the prologue.
        include SlidingNonce::RecordNonceAbortsIf{account: tc_account, seq_nonce: sliding_nonce};
        include DiemAccount::CreateDesignatedDealerAbortsIf<Currency>{
            creator_account: tc_account, new_account_address: addr};
        include DiemAccount::CreateDesignatedDealerEnsures<Currency>{new_account_address: addr};

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::REQUIRES_ADDRESS,
            Errors::NOT_PUBLISHED,
            Errors::ALREADY_PUBLISHED,
            Errors::REQUIRES_ROLE;

        include DiemAccount::MakeAccountEmits{new_account_address: addr};

        /// **Access Control:**
        /// Only the Treasury Compliance account can create Designated Dealer accounts [[A5]][ROLE].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
    }
}
