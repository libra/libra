/// This module holds transactions that can be used to administer accounts in the Diem Framework.
module DiemFramework::AccountAdministrationScripts {
    use DiemFramework::DiemAccount;
    use DiemFramework::RecoveryAddress;
    use DiemFramework::SharedEd25519PublicKey;
    use DiemFramework::SlidingNonce;
    use DiemFramework::DualAttestation;
    use DiemFramework::VASPDomain;

    /// # Summary
    /// Adds a zero `Currency` balance to the sending `account`. This will enable `account` to
    /// send, receive, and hold `Diem::Diem<Currency>` coins. This transaction can be
    /// successfully sent by any account that is allowed to hold balances
    /// (e.g., VASP, Designated Dealer).
    ///
    /// # Technical Description
    /// After the successful execution of this transaction the sending account will have a
    /// `DiemAccount::Balance<Currency>` resource with zero balance published under it. Only
    /// accounts that can hold balances can send this transaction, the sending account cannot
    /// already have a `DiemAccount::Balance<Currency>` published under it.
    ///
    /// # Parameters
    /// | Name       | Type     | Description                                                                                                                                         |
    /// | ------     | ------   | -------------                                                                                                                                       |
    /// | `Currency` | Type     | The Move type for the `Currency` being added to the sending account of the transaction. `Currency` must be an already-registered currency on-chain. |
    /// | `account`  | `signer` | The signer of the sending account of the transaction.                                                                                               |
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason                             | Description                                                                |
    /// | ----------------            | --------------                           | -------------                                                              |
    /// | `Errors::NOT_PUBLISHED`     | `Diem::ECURRENCY_INFO`                  | The `Currency` is not a registered currency on-chain.                      |
    /// | `Errors::INVALID_ARGUMENT`  | `DiemAccount::EROLE_CANT_STORE_BALANCE` | The sending `account`'s role does not permit balances.                     |
    /// | `Errors::ALREADY_PUBLISHED` | `DiemAccount::EADD_EXISTING_CURRENCY`   | A balance for `Currency` is already published under the sending `account`. |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_child_vasp_account`
    /// * `AccountCreationScripts::create_parent_vasp_account`
    /// * `PaymentScripts::peer_to_peer_with_metadata`

    public(script) fun add_currency_to_account<Currency>(account: signer) {
        DiemAccount::add_currency<Currency>(&account);
    }
    spec add_currency_to_account {
        use Std::Errors;
        use Std::Signer;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include DiemAccount::AddCurrencyAbortsIf<Currency>;
        include DiemAccount::AddCurrencyEnsures<Currency>{addr: Signer::spec_address_of(account)};

        aborts_with [check]
            Errors::NOT_PUBLISHED,
            Errors::INVALID_ARGUMENT,
            Errors::ALREADY_PUBLISHED;

        /// **Access Control:**
        /// The account must be allowed to hold balances. Only Designated Dealers, Parent VASPs,
        /// and Child VASPs can hold balances [[D1]][ROLE][[D2]][ROLE][[D3]][ROLE][[D4]][ROLE][[D5]][ROLE][[D6]][ROLE][[D7]][ROLE].
        aborts_if !Roles::can_hold_balance(account) with Errors::INVALID_ARGUMENT;
    }

    /// # Summary
    /// Stores the sending accounts ability to rotate its authentication key with a designated recovery
    /// account. Both the sending and recovery accounts need to belong to the same VASP and
    /// both be VASP accounts. After this transaction both the sending account and the
    /// specified recovery account can rotate the sender account's authentication key.
    ///
    /// # Technical Description
    /// Adds the `DiemAccount::KeyRotationCapability` for the sending account
    /// (`to_recover_account`) to the `RecoveryAddress::RecoveryAddress` resource under
    /// `recovery_address`. After this transaction has been executed successfully the account at
    /// `recovery_address` and the `to_recover_account` may rotate the authentication key of
    /// `to_recover_account` (the sender of this transaction).
    ///
    /// The sending account of this transaction (`to_recover_account`) must not have previously given away its unique key
    /// rotation capability, and must be a VASP account. The account at `recovery_address`
    /// must also be a VASP account belonging to the same VASP as the `to_recover_account`.
    /// Additionally the account at `recovery_address` must have already initialized itself as
    /// a recovery account address using the `AccountAdministrationScripts::create_recovery_address` transaction script.
    ///
    /// The sending account's (`to_recover_account`) key rotation capability is
    /// removed in this transaction and stored in the `RecoveryAddress::RecoveryAddress`
    /// resource stored under the account at `recovery_address`.
    ///
    /// # Parameters
    /// | Name                 | Type      | Description                                                                                               |
    /// | ------               | ------    | -------------                                                                                             |
    /// | `to_recover_account` | `signer`  | The signer of the sending account of this transaction.                                                    |
    /// | `recovery_address`   | `address` | The account address where the `to_recover_account`'s `DiemAccount::KeyRotationCapability` will be stored. |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                              | Description                                                                                       |
    /// | ----------------           | --------------                                            | -------------                                                                                     |
    /// | `Errors::INVALID_STATE`    | `DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED` | `to_recover_account` has already delegated/extracted its `DiemAccount::KeyRotationCapability`.    |
    /// | `Errors::NOT_PUBLISHED`    | `RecoveryAddress::ERECOVERY_ADDRESS`                      | `recovery_address` does not have a `RecoveryAddress` resource published under it.                 |
    /// | `Errors::INVALID_ARGUMENT` | `RecoveryAddress::EINVALID_KEY_ROTATION_DELEGATION`       | `to_recover_account` and `recovery_address` do not belong to the same VASP.                       |
    /// | `Errors::LIMIT_EXCEEDED`   | ` RecoveryAddress::EMAX_KEYS_REGISTERED`                  | `RecoveryAddress::MAX_REGISTERED_KEYS` have already been registered with this `recovery_address`. |
    ///
    /// # Related Scripts
    /// * `AccountAdministrationScripts::create_recovery_address`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_recovery_address`

    public(script) fun add_recovery_rotation_capability(to_recover_account: signer, recovery_address: address) {
        RecoveryAddress::add_rotation_capability(
            DiemAccount::extract_key_rotation_capability(&to_recover_account), recovery_address
        )
    }
    spec add_recovery_rotation_capability {
        use Std::Signer;
        use Std::Errors;

        include DiemAccount::TransactionChecks{sender: to_recover_account}; // properties checked by the prologue.
        include DiemAccount::ExtractKeyRotationCapabilityAbortsIf{account: to_recover_account};
        include DiemAccount::ExtractKeyRotationCapabilityEnsures{account: to_recover_account};

        let addr = Signer::spec_address_of(to_recover_account);
        let rotation_cap = DiemAccount::spec_get_key_rotation_cap(addr);

        include RecoveryAddress::AddRotationCapabilityAbortsIf{
            to_recover: rotation_cap
        };

        ensures RecoveryAddress::spec_get_rotation_caps(recovery_address)[
            len(RecoveryAddress::spec_get_rotation_caps(recovery_address)) - 1] == rotation_cap;

        aborts_with [check]
            Errors::INVALID_STATE,
            Errors::NOT_PUBLISHED,
            Errors::LIMIT_EXCEEDED,
            Errors::INVALID_ARGUMENT;
    }

    /// # Summary
    /// Rotates the authentication key of the sending account to the newly-specified ed25519 public key and
    /// publishes a new shared authentication key derived from that public key under the sender's account.
    /// Any account can send this transaction.
    ///
    /// # Technical Description
    /// Rotates the authentication key of the sending account to the
    /// [authentication key derived from `public_key`](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys)
    /// and publishes a `SharedEd25519PublicKey::SharedEd25519PublicKey` resource
    /// containing the 32-byte ed25519 `public_key` and the `DiemAccount::KeyRotationCapability` for
    /// `account` under `account`.
    ///
    /// # Parameters
    /// | Name         | Type         | Description                                                                                        |
    /// | ------       | ------       | -------------                                                                                      |
    /// | `account`    | `signer`     | The signer of the sending account of the transaction.                                              |
    /// | `public_key` | `vector<u8>` | A valid 32-byte Ed25519 public key for `account`'s authentication key to be rotated to and stored. |
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason                                               | Description                                                                                         |
    /// | ----------------            | --------------                                             | -------------                                                                                       |
    /// | `Errors::INVALID_STATE`     | `DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED` | `account` has already delegated/extracted its `DiemAccount::KeyRotationCapability` resource.       |
    /// | `Errors::ALREADY_PUBLISHED` | `SharedEd25519PublicKey::ESHARED_KEY`                      | The `SharedEd25519PublicKey::SharedEd25519PublicKey` resource is already published under `account`. |
    /// | `Errors::INVALID_ARGUMENT`  | `SharedEd25519PublicKey::EMALFORMED_PUBLIC_KEY`            | `public_key` is an invalid ed25519 public key.                                                      |
    ///
    /// # Related Scripts
    /// * `AccountAdministrationScripts::rotate_shared_ed25519_public_key`

    public(script) fun publish_shared_ed25519_public_key(account: signer, public_key: vector<u8>) {
        SharedEd25519PublicKey::publish(&account, public_key)
    }
    spec publish_shared_ed25519_public_key {
        use Std::Errors;
        use DiemFramework::DiemAccount;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include SharedEd25519PublicKey::PublishAbortsIf{key: public_key};
        include SharedEd25519PublicKey::PublishEnsures{key: public_key};

        aborts_with [check]
            Errors::INVALID_STATE,
            Errors::ALREADY_PUBLISHED,
            Errors::INVALID_ARGUMENT;
    }

    /// # Summary
    /// Rotates the `account`'s authentication key to the supplied new authentication key. May be sent by any account.
    ///
    /// # Technical Description
    /// Rotate the `account`'s `DiemAccount::DiemAccount` `authentication_key`
    /// field to `new_key`. `new_key` must be a valid authentication key that
    /// corresponds to an ed25519 public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
    /// and `account` must not have previously delegated its `DiemAccount::KeyRotationCapability`.
    ///
    /// # Parameters
    /// | Name      | Type         | Description                                       |
    /// | ------    | ------       | -------------                                     |
    /// | `account` | `signer`     | Signer of the sending account of the transaction. |
    /// | `new_key` | `vector<u8>` | New authentication key to be used for `account`.  |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                              | Description                                                                         |
    /// | ----------------           | --------------                                            | -------------                                                                       |
    /// | `Errors::INVALID_STATE`    | `DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED` | `account` has already delegated/extracted its `DiemAccount::KeyRotationCapability`. |
    /// | `Errors::INVALID_ARGUMENT` | `DiemAccount::EMALFORMED_AUTHENTICATION_KEY`              | `new_key` was an invalid length.                                                    |
    ///
    /// # Related Scripts
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_nonce`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_recovery_address`

    public(script) fun rotate_authentication_key(account: signer, new_key: vector<u8>) {
        let key_rotation_capability = DiemAccount::extract_key_rotation_capability(&account);
        DiemAccount::rotate_authentication_key(&key_rotation_capability, new_key);
        DiemAccount::restore_key_rotation_capability(key_rotation_capability);
    }
    spec rotate_authentication_key {
        use Std::Signer;
        use Std::Errors;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        let account_addr = Signer::spec_address_of(account);
        include DiemAccount::ExtractKeyRotationCapabilityAbortsIf;
        let key_rotation_capability = DiemAccount::spec_get_key_rotation_cap(account_addr);
        include DiemAccount::RotateAuthenticationKeyAbortsIf{cap: key_rotation_capability, new_authentication_key: new_key};

        /// This rotates the authentication key of `account` to `new_key`
        include DiemAccount::RotateAuthenticationKeyEnsures{addr: account_addr, new_authentication_key: new_key};

        aborts_with [check]
            Errors::INVALID_STATE,
            Errors::INVALID_ARGUMENT;

        /// **Access Control:**
        /// The account can rotate its own authentication key unless
        /// it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].
        include DiemAccount::AbortsIfDelegatedKeyRotationCapability;
    }

    /// # Summary
    /// Rotates the sender's authentication key to the supplied new authentication key. May be sent by
    /// any account that has a sliding nonce resource published under it (usually this is Treasury
    /// Compliance or Diem Root accounts).
    ///
    /// # Technical Description
    /// Rotates the `account`'s `DiemAccount::DiemAccount` `authentication_key`
    /// field to `new_key`. `new_key` must be a valid authentication key that
    /// corresponds to an ed25519 public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
    /// and `account` must not have previously delegated its `DiemAccount::KeyRotationCapability`.
    ///
    /// # Parameters
    /// | Name            | Type         | Description                                                                |
    /// | ------          | ------       | -------------                                                              |
    /// | `account`       | `signer`     | Signer of the sending account of the transaction.                          |
    /// | `sliding_nonce` | `u64`        | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction. |
    /// | `new_key`       | `vector<u8>` | New authentication key to be used for `account`.                           |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                               | Description                                                                                |
    /// | ----------------           | --------------                                             | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`    | `SlidingNonce::ESLIDING_NONCE`                             | A `SlidingNonce` resource is not published under `account`.                                |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_OLD`                             | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_NEW`                             | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_ALREADY_RECORDED`                    | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::INVALID_STATE`    | `DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED` | `account` has already delegated/extracted its `DiemAccount::KeyRotationCapability`.       |
    /// | `Errors::INVALID_ARGUMENT` | `DiemAccount::EMALFORMED_AUTHENTICATION_KEY`              | `new_key` was an invalid length.                                                           |
    ///
    /// # Related Scripts
    /// * `AccountAdministrationScripts::rotate_authentication_key`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_recovery_address`

    public(script) fun rotate_authentication_key_with_nonce(account: signer, sliding_nonce: u64, new_key: vector<u8>) {
        SlidingNonce::record_nonce_or_abort(&account, sliding_nonce);
        let key_rotation_capability = DiemAccount::extract_key_rotation_capability(&account);
        DiemAccount::rotate_authentication_key(&key_rotation_capability, new_key);
        DiemAccount::restore_key_rotation_capability(key_rotation_capability);
    }
    spec rotate_authentication_key_with_nonce {
        use Std::Signer;
        use Std::Errors;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        let account_addr = Signer::spec_address_of(account);
        include SlidingNonce::RecordNonceAbortsIf{ seq_nonce: sliding_nonce };
        include DiemAccount::ExtractKeyRotationCapabilityAbortsIf;
        let key_rotation_capability = DiemAccount::spec_get_key_rotation_cap(account_addr);
        include DiemAccount::RotateAuthenticationKeyAbortsIf{cap: key_rotation_capability, new_authentication_key: new_key};

        /// This rotates the authentication key of `account` to `new_key`
        include DiemAccount::RotateAuthenticationKeyEnsures{addr: account_addr, new_authentication_key: new_key};

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::INVALID_STATE,
            Errors::NOT_PUBLISHED;

        /// **Access Control:**
        /// The account can rotate its own authentication key unless
        /// it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].
        include DiemAccount::AbortsIfDelegatedKeyRotationCapability;
    }

    /// # Summary
    /// Rotates the specified account's authentication key to the supplied new authentication key. May
    /// only be sent by the Diem Root account as a write set transaction.
    ///
    /// # Technical Description
    /// Rotate the `account`'s `DiemAccount::DiemAccount` `authentication_key` field to `new_key`.
    /// `new_key` must be a valid authentication key that corresponds to an ed25519
    /// public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
    /// and `account` must not have previously delegated its `DiemAccount::KeyRotationCapability`.
    ///
    /// # Parameters
    /// | Name            | Type         | Description                                                                                       |
    /// | ------          | ------       | -------------                                                                                     |
    /// | `dr_account`    | `signer`     | The signer of the sending account of the write set transaction. May only be the Diem Root signer. |
    /// | `account`       | `signer`     | Signer of account specified in the `execute_as` field of the write set transaction.               |
    /// | `sliding_nonce` | `u64`        | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction for Diem Root.          |
    /// | `new_key`       | `vector<u8>` | New authentication key to be used for `account`.                                                  |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                              | Description                                                                                                |
    /// | ----------------           | --------------                                            | -------------                                                                                              |
    /// | `Errors::NOT_PUBLISHED`    | `SlidingNonce::ESLIDING_NONCE`                            | A `SlidingNonce` resource is not published under `dr_account`.                                             |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_OLD`                            | The `sliding_nonce` in `dr_account` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_NEW`                            | The `sliding_nonce` in `dr_account` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_ALREADY_RECORDED`                   | The `sliding_nonce` in` dr_account` has been previously recorded.                                          |
    /// | `Errors::INVALID_STATE`    | `DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED` | `account` has already delegated/extracted its `DiemAccount::KeyRotationCapability`.                        |
    /// | `Errors::INVALID_ARGUMENT` | `DiemAccount::EMALFORMED_AUTHENTICATION_KEY`              | `new_key` was an invalid length.                                                                           |
    ///
    /// # Related Scripts
    /// * `AccountAdministrationScripts::rotate_authentication_key`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_nonce`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_recovery_address`

    public(script) fun rotate_authentication_key_with_nonce_admin(dr_account: signer, account: signer, sliding_nonce: u64, new_key: vector<u8>) {
        SlidingNonce::record_nonce_or_abort(&dr_account, sliding_nonce);
        let key_rotation_capability = DiemAccount::extract_key_rotation_capability(&account);
        DiemAccount::rotate_authentication_key(&key_rotation_capability, new_key);
        DiemAccount::restore_key_rotation_capability(key_rotation_capability);
    }
    spec rotate_authentication_key_with_nonce_admin {
        use Std::Signer;
        use Std::Errors;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        let account_addr = Signer::spec_address_of(account);
        include SlidingNonce::RecordNonceAbortsIf{ account: dr_account, seq_nonce: sliding_nonce };
        include DiemAccount::ExtractKeyRotationCapabilityAbortsIf;
        let key_rotation_capability = DiemAccount::spec_get_key_rotation_cap(account_addr);
        include DiemAccount::RotateAuthenticationKeyAbortsIf{cap: key_rotation_capability, new_authentication_key: new_key};

        /// This rotates the authentication key of `account` to `new_key`
        include DiemAccount::RotateAuthenticationKeyEnsures{addr: account_addr, new_authentication_key: new_key};

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::INVALID_STATE,
            Errors::NOT_PUBLISHED;

        /// **Access Control:**
        /// Only the Diem Root account can process the admin scripts [[H9]][PERMISSION].
        requires Roles::has_diem_root_role(dr_account); /// This is ensured by DiemAccount::writeset_prologue.
        /// The account can rotate its own authentication key unless
        /// it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].
        include DiemAccount::AbortsIfDelegatedKeyRotationCapability{account: account};
    }

    /// # Summary
    /// Rotates the authentication key of a specified account that is part of a recovery address to a
    /// new authentication key. Only used for accounts that are part of a recovery address (see
    /// `AccountAdministrationScripts::add_recovery_rotation_capability` for account restrictions).
    ///
    /// # Technical Description
    /// Rotates the authentication key of the `to_recover` account to `new_key` using the
    /// `DiemAccount::KeyRotationCapability` stored in the `RecoveryAddress::RecoveryAddress` resource
    /// published under `recovery_address`. `new_key` must be a valide authentication key as described
    /// [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).
    /// This transaction can be sent either by the `to_recover` account, or by the account where the
    /// `RecoveryAddress::RecoveryAddress` resource is published that contains `to_recover`'s `DiemAccount::KeyRotationCapability`.
    ///
    /// # Parameters
    /// | Name               | Type         | Description                                                                                                                   |
    /// | ------             | ------       | -------------                                                                                                                 |
    /// | `account`          | `signer`     | Signer of the sending account of the transaction.                                                                             |
    /// | `recovery_address` | `address`    | Address where `RecoveryAddress::RecoveryAddress` that holds `to_recover`'s `DiemAccount::KeyRotationCapability` is published. |
    /// | `to_recover`       | `address`    | The address of the account whose authentication key will be updated.                                                          |
    /// | `new_key`          | `vector<u8>` | New authentication key to be used for the account at the `to_recover` address.                                                |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                 | Description                                                                                                                                         |
    /// | ----------------           | --------------                               | -------------                                                                                                                                       |
    /// | `Errors::NOT_PUBLISHED`    | `RecoveryAddress::ERECOVERY_ADDRESS`         | `recovery_address` does not have a `RecoveryAddress::RecoveryAddress` resource published under it.                                                  |
    /// | `Errors::INVALID_ARGUMENT` | `RecoveryAddress::ECANNOT_ROTATE_KEY`        | The address of `account` is not `recovery_address` or `to_recover`.                                                                                 |
    /// | `Errors::INVALID_ARGUMENT` | `RecoveryAddress::EACCOUNT_NOT_RECOVERABLE`  | `to_recover`'s `DiemAccount::KeyRotationCapability`  is not in the `RecoveryAddress::RecoveryAddress`  resource published under `recovery_address`. |
    /// | `Errors::INVALID_ARGUMENT` | `DiemAccount::EMALFORMED_AUTHENTICATION_KEY` | `new_key` was an invalid length.                                                                                                                    |
    ///
    /// # Related Scripts
    /// * `AccountAdministrationScripts::rotate_authentication_key`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_nonce`
    /// * `AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin`

    public(script) fun rotate_authentication_key_with_recovery_address(
            account: signer,
            recovery_address: address,
            to_recover: address,
            new_key: vector<u8>
            ) {
        RecoveryAddress::rotate_authentication_key(&account, recovery_address, to_recover, new_key)
    }
    spec rotate_authentication_key_with_recovery_address {
        use Std::Errors;
        use DiemFramework::DiemAccount;
        use Std::Signer;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include RecoveryAddress::RotateAuthenticationKeyAbortsIf;
        include RecoveryAddress::RotateAuthenticationKeyEnsures;

        aborts_with [check]
            Errors::NOT_PUBLISHED,
            Errors::INVALID_ARGUMENT;

        /// **Access Control:**
        /// The delegatee at the recovery address has to hold the key rotation capability for
        /// the address to recover. The address of the transaction signer has to be either
        /// the delegatee's address or the address to recover [[H18]][PERMISSION][[J18]][PERMISSION].
        let account_addr = Signer::spec_address_of(account);
        aborts_if !RecoveryAddress::spec_holds_key_rotation_cap_for(recovery_address, to_recover) with Errors::INVALID_ARGUMENT;
        aborts_if !(account_addr == recovery_address || account_addr == to_recover) with Errors::INVALID_ARGUMENT;
    }

    /// # Summary
    /// Updates the url used for off-chain communication, and the public key used to verify dual
    /// attestation on-chain. Transaction can be sent by any account that has dual attestation
    /// information published under it. In practice the only such accounts are Designated Dealers and
    /// Parent VASPs.
    ///
    /// # Technical Description
    /// Updates the `base_url` and `compliance_public_key` fields of the `DualAttestation::Credential`
    /// resource published under `account`. The `new_key` must be a valid ed25519 public key.
    ///
    /// # Events
    /// Successful execution of this transaction emits two events:
    /// * A `DualAttestation::ComplianceKeyRotationEvent` containing the new compliance public key, and
    /// the blockchain time at which the key was updated emitted on the `DualAttestation::Credential`
    /// `compliance_key_rotation_events` handle published under `account`; and
    /// * A `DualAttestation::BaseUrlRotationEvent` containing the new base url to be used for
    /// off-chain communication, and the blockchain time at which the url was updated emitted on the
    /// `DualAttestation::Credential` `base_url_rotation_events` handle published under `account`.
    ///
    /// # Parameters
    /// | Name      | Type         | Description                                                               |
    /// | ------    | ------       | -------------                                                             |
    /// | `account` | `signer`     | Signer of the sending account of the transaction.                         |
    /// | `new_url` | `vector<u8>` | ASCII-encoded url to be used for off-chain communication with `account`.  |
    /// | `new_key` | `vector<u8>` | New ed25519 public key to be used for on-chain dual attestation checking. |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                           | Description                                                                |
    /// | ----------------           | --------------                         | -------------                                                              |
    /// | `Errors::NOT_PUBLISHED`    | `DualAttestation::ECREDENTIAL`         | A `DualAttestation::Credential` resource is not published under `account`. |
    /// | `Errors::INVALID_ARGUMENT` | `DualAttestation::EINVALID_PUBLIC_KEY` | `new_key` is not a valid ed25519 public key.                               |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_parent_vasp_account`
    /// * `AccountCreationScripts::create_designated_dealer`
    /// * `AccountAdministrationScripts::rotate_dual_attestation_info`

    public(script) fun rotate_dual_attestation_info(account: signer, new_url: vector<u8>, new_key: vector<u8>) {
        DualAttestation::rotate_base_url(&account, new_url);
        DualAttestation::rotate_compliance_public_key(&account, new_key)
    }
    spec rotate_dual_attestation_info {
        use Std::Errors;
        use DiemFramework::DiemAccount;
        use Std::Signer;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include DualAttestation::RotateBaseUrlAbortsIf;
        include DualAttestation::RotateBaseUrlEnsures;
        include DualAttestation::RotateCompliancePublicKeyAbortsIf;
        include DualAttestation::RotateCompliancePublicKeyEnsures;

        aborts_with [check]
            Errors::NOT_PUBLISHED,
            Errors::INVALID_ARGUMENT;

        include DualAttestation::RotateBaseUrlEmits;
        include DualAttestation::RotateCompliancePublicKeyEmits;

        /// **Access Control:**
        /// Only the account having Credential can rotate the info.
        /// Credential is granted to either a Parent VASP or a designated dealer [[H17]][PERMISSION].
        include DualAttestation::AbortsIfNoCredential{addr: Signer::spec_address_of(account)};
    }

    /// # Summary
    /// Rotates the authentication key in a `SharedEd25519PublicKey`. This transaction can be sent by
    /// any account that has previously published a shared ed25519 public key using
    /// `AccountAdministrationScripts::publish_shared_ed25519_public_key`.
    ///
    /// # Technical Description
    /// `public_key` must be a valid ed25519 public key.  This transaction first rotates the public key stored in `account`'s
    /// `SharedEd25519PublicKey::SharedEd25519PublicKey` resource to `public_key`, after which it
    /// rotates the `account`'s authentication key to the new authentication key derived from `public_key` as defined
    /// [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys)
    /// using the `DiemAccount::KeyRotationCapability` stored in `account`'s `SharedEd25519PublicKey::SharedEd25519PublicKey`.
    ///
    /// # Parameters
    /// | Name         | Type         | Description                                           |
    /// | ------       | ------       | -------------                                         |
    /// | `account`    | `signer`     | The signer of the sending account of the transaction. |
    /// | `public_key` | `vector<u8>` | 32-byte Ed25519 public key.                           |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                    | Description                                                                                   |
    /// | ----------------           | --------------                                  | -------------                                                                                 |
    /// | `Errors::NOT_PUBLISHED`    | `SharedEd25519PublicKey::ESHARED_KEY`           | A `SharedEd25519PublicKey::SharedEd25519PublicKey` resource is not published under `account`. |
    /// | `Errors::INVALID_ARGUMENT` | `SharedEd25519PublicKey::EMALFORMED_PUBLIC_KEY` | `public_key` is an invalid ed25519 public key.                                                |
    ///
    /// # Related Scripts
    /// * `AccountAdministrationScripts::publish_shared_ed25519_public_key`

    public(script) fun rotate_shared_ed25519_public_key(account: signer, public_key: vector<u8>) {
        SharedEd25519PublicKey::rotate_key(&account, public_key)
    }
    spec rotate_shared_ed25519_public_key {
        use Std::Errors;
        use DiemFramework::DiemAccount;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include SharedEd25519PublicKey::RotateKeyAbortsIf{new_public_key: public_key};
        include SharedEd25519PublicKey::RotateKeyEnsures{new_public_key: public_key};

        aborts_with [check]
            Errors::NOT_PUBLISHED,
            Errors::INVALID_ARGUMENT;
    }

    /// # Summary
    /// Initializes the sending account as a recovery address that may be used by
    /// other accounts belonging to the same VASP as `account`.
    /// The sending account must be a VASP account, and can be either a child or parent VASP account.
    /// Multiple recovery addresses can exist for a single VASP, but accounts in
    /// each must be disjoint.
    ///
    /// # Technical Description
    /// Publishes a `RecoveryAddress::RecoveryAddress` resource under `account`. It then
    /// extracts the `DiemAccount::KeyRotationCapability` for `account` and adds
    /// it to the resource. After the successful execution of this transaction
    /// other accounts may add their key rotation to this resource so that `account`
    /// may be used as a recovery account for those accounts.
    ///
    /// # Parameters
    /// | Name      | Type     | Description                                           |
    /// | ------    | ------   | -------------                                         |
    /// | `account` | `signer` | The signer of the sending account of the transaction. |
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason                                               | Description                                                                                   |
    /// | ----------------            | --------------                                             | -------------                                                                                 |
    /// | `Errors::INVALID_STATE`     | `DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED` | `account` has already delegated/extracted its `DiemAccount::KeyRotationCapability`.          |
    /// | `Errors::INVALID_ARGUMENT`  | `RecoveryAddress::ENOT_A_VASP`                             | `account` is not a VASP account.                                                              |
    /// | `Errors::INVALID_ARGUMENT`  | `RecoveryAddress::EKEY_ROTATION_DEPENDENCY_CYCLE`          | A key rotation recovery cycle would be created by adding `account`'s key rotation capability. |
    /// | `Errors::ALREADY_PUBLISHED` | `RecoveryAddress::ERECOVERY_ADDRESS`                       | A `RecoveryAddress::RecoveryAddress` resource has already been published under `account`.     |
    ///
    /// # Related Scripts
    /// * `Script::add_recovery_rotation_capability`
    /// * `Script::rotate_authentication_key_with_recovery_address`

    public(script) fun create_recovery_address(account: signer) {
        RecoveryAddress::publish(&account, DiemAccount::extract_key_rotation_capability(&account))
    }

    spec create_recovery_address {
        use Std::Signer;
        use Std::Errors;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include DiemAccount::ExtractKeyRotationCapabilityAbortsIf;
        include DiemAccount::ExtractKeyRotationCapabilityEnsures;

        let account_addr = Signer::spec_address_of(account);
        let rotation_cap = DiemAccount::spec_get_key_rotation_cap(account_addr);

        include RecoveryAddress::PublishAbortsIf{
            recovery_account: account,
            rotation_cap: rotation_cap
        };

        ensures RecoveryAddress::spec_is_recovery_address(account_addr);
        ensures len(RecoveryAddress::spec_get_rotation_caps(account_addr)) == 1;
        ensures RecoveryAddress::spec_get_rotation_caps(account_addr)[0] == rotation_cap;

        aborts_with [check]
            Errors::INVALID_STATE,
            Errors::INVALID_ARGUMENT,
            Errors::ALREADY_PUBLISHED;
    }

    /// # Summary
    /// Publishes a `VASPDomain::VASPDomains` resource under a parent VASP account.
    /// The sending account must be a parent VASP account.
    ///
    /// # Technical Description
    /// Publishes a `VASPDomain::VASPDomains` resource under `account`.
    /// The The `VASPDomain::VASPDomains` resource's `domains` field is a vector
    /// of VASPDomain, and will be empty on at the end of processing this transaction.
    ///
    /// # Parameters
    /// | Name      | Type     | Description                                           |
    /// | ------    | ------   | -------------                                         |
    /// | `account` | `signer` | The signer of the sending account of the transaction. |
    ///
    /// # Common Abort Conditions
    /// | Error Category              | Error Reason              | Description                                                                    |
    /// | ----------------            | --------------            | -------------                                                                  |
    /// | `Errors::ALREADY_PUBLISHED` | `VASPDomain::EVASP_DOMAINS` | A `VASPDomain::VASPDomains` resource has already been published under `account`. |
    /// | `Errors::REQUIRES_ROLE`     | `Roles::EPARENT_VASP`     | The sending `account` was not a parent VASP account.                           |
    public(script) fun create_vasp_domains(account: signer) {
        VASPDomain::publish_vasp_domains(&account)
    }
    spec create_vasp_domains {
        use DiemFramework::Roles;
        use Std::Errors;
        use Std::Signer;

        let vasp_addr = Signer::spec_address_of(account);
        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include Roles::AbortsIfNotParentVasp;
        include VASPDomain::PublishVASPDomainsAbortsIf { vasp_addr };
        include VASPDomain::PublishVASPDomainsEnsures { vasp_addr };

        aborts_with [check]
            Errors::ALREADY_PUBLISHED,
            Errors::REQUIRES_ROLE;
    }
}
