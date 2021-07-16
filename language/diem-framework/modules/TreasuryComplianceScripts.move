/// This module holds scripts relating to treasury and compliance-related
/// activities in the Diem Framework.
///
/// Only accounts with a role of `Roles::TREASURY_COMPLIANCE` and
/// `Roles::DESIGNATED_DEALER` can (successfully) use the scripts in this
/// module. The exact role required for a transaction is determined on a
/// per-transaction basis.
module DiemFramework::TreasuryComplianceScripts {
    use DiemFramework::DiemAccount;
    use DiemFramework::Diem;
    use DiemFramework::SlidingNonce;
    use DiemFramework::TransactionFee;
    use DiemFramework::AccountFreezing;
    use DiemFramework::DualAttestation;
    use DiemFramework::VASPDomain;
    use Std::FixedPoint32;

    /// # Summary
    /// Cancels and returns the coins held in the preburn area under
    /// `preburn_address`, which are equal to the `amount` specified in the transaction. Finds the first preburn
    /// resource with the matching amount and returns the funds to the `preburn_address`'s balance.
    /// Can only be successfully sent by an account with Treasury Compliance role.
    ///
    /// # Technical Description
    /// Cancels and returns all coins held in the `Diem::Preburn<Token>` resource under the `preburn_address` and
    /// return the funds to the `preburn_address` account's `DiemAccount::Balance<Token>`.
    /// The transaction must be sent by an `account` with a `Diem::BurnCapability<Token>`
    /// resource published under it. The account at `preburn_address` must have a
    /// `Diem::Preburn<Token>` resource published under it, and its value must be nonzero. The transaction removes
    /// the entire balance held in the `Diem::Preburn<Token>` resource, and returns it back to the account's
    /// `DiemAccount::Balance<Token>` under `preburn_address`. Due to this, the account at
    /// `preburn_address` must already have a balance in the `Token` currency published
    /// before this script is called otherwise the transaction will fail.
    ///
    /// # Events
    /// The successful execution of this transaction will emit:
    /// * A `Diem::CancelBurnEvent` on the event handle held in the `Diem::CurrencyInfo<Token>`
    /// resource's `burn_events` published under `0xA550C18`.
    /// * A `DiemAccount::ReceivedPaymentEvent` on the `preburn_address`'s
    /// `DiemAccount::DiemAccount` `received_events` event handle with both the `payer` and `payee`
    /// being `preburn_address`.
    ///
    /// # Parameters
    /// | Name              | Type      | Description                                                                                                                          |
    /// | ------            | ------    | -------------                                                                                                                        |
    /// | `Token`           | Type      | The Move type for the `Token` currenty that burning is being cancelled for. `Token` must be an already-registered currency on-chain. |
    /// | `account`         | `signer`  | The signer of the sending account of this transaction, must have a burn capability for `Token` published under it.                   |
    /// | `preburn_address` | `address` | The address where the coins to-be-burned are currently held.                                                                         |
    /// | `amount`          | `u64`     | The amount to be cancelled.                                                                                                          |
    ///
    /// # Common Abort Conditions
    /// | Error Category                | Error Reason                                     | Description                                                                                                                         |
    /// | ----------------              | --------------                                   | -------------                                                                                                                       |
    /// | `Errors::REQUIRES_CAPABILITY` | `Diem::EBURN_CAPABILITY`                         | The sending `account` does not have a `Diem::BurnCapability<Token>` published under it.                                             |
    /// | `Errors::INVALID_STATE`       | `Diem::EPREBURN_NOT_FOUND`                       | The `Diem::PreburnQueue<Token>` resource under `preburn_address` does not contain a preburn request with a value matching `amount`. |
    /// | `Errors::NOT_PUBLISHED`       | `Diem::EPREBURN_QUEUE`                           | The account at `preburn_address` does not have a `Diem::PreburnQueue<Token>` resource published under it.                           |
    /// | `Errors::NOT_PUBLISHED`       | `Diem::ECURRENCY_INFO`                           | The specified `Token` is not a registered currency on-chain.                                                                        |
    /// | `Errors::INVALID_ARGUMENT`    | `DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE`  | The account at `preburn_address` doesn't have a balance resource for `Token`.                                                       |
    /// | `Errors::LIMIT_EXCEEDED`      | `DiemAccount::EDEPOSIT_EXCEEDS_LIMITS`           | The depositing of the funds held in the prebun area would exceed the `account`'s account limits.                                    |
    /// | `Errors::INVALID_STATE`       | `DualAttestation::EPAYEE_COMPLIANCE_KEY_NOT_SET` | The `account` does not have a compliance key set on it but dual attestion checking was performed.                                   |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::burn_txn_fees`
    /// * `TreasuryComplianceScripts::burn_with_amount`
    /// * `TreasuryComplianceScripts::preburn`

    public(script) fun cancel_burn_with_amount<Token>(account: signer, preburn_address: address, amount: u64) {
        DiemAccount::cancel_burn<Token>(&account, preburn_address, amount)
    }

    spec cancel_burn_with_amount {
        use Std::Errors;
        use DiemFramework::Diem;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include DiemAccount::CancelBurnAbortsIf<Token>;
        include Diem::CancelBurnWithCapEnsures<Token>;
        include DiemAccount::DepositEnsures<Token>{payee: preburn_address};

        let total_preburn_value = global<Diem::CurrencyInfo<Token>>(
            @CurrencyInfo
        ).preburn_value;
        let post post_total_preburn_value = global<Diem::CurrencyInfo<Token>>(
            @CurrencyInfo
        ).preburn_value;

        let balance_at_addr = DiemAccount::balance<Token>(preburn_address);
        let post post_balance_at_addr = DiemAccount::balance<Token>(preburn_address);

        /// The total value of preburn for `Token` should decrease by the preburned amount.
        ensures post_total_preburn_value == total_preburn_value - amount;

        /// The balance of `Token` at `preburn_address` should increase by the preburned amount.
        ensures post_balance_at_addr == balance_at_addr + amount;

        include Diem::CancelBurnWithCapEmits<Token>;
        include DiemAccount::DepositEmits<Token>{
            payer: preburn_address,
            payee: preburn_address,
            amount: amount,
            metadata: x""
        };

        aborts_with [check]
            Errors::REQUIRES_CAPABILITY,
            Errors::NOT_PUBLISHED,
            Errors::INVALID_ARGUMENT,
            Errors::LIMIT_EXCEEDED,
            Errors::INVALID_STATE;

        /// **Access Control:**
        /// Only the account with the burn capability can cancel burning [[H3]][PERMISSION].
        include Diem::AbortsIfNoBurnCapability<Token>{account: account};
    }

    /// # Summary
    /// Burns the coins held in a preburn resource in the preburn queue at the
    /// specified preburn address, which are equal to the `amount` specified in the
    /// transaction. Finds the first relevant outstanding preburn request with
    /// matching amount and removes the contained coins from the system. The sending
    /// account must be the Treasury Compliance account.
    /// The account that holds the preburn queue resource will normally be a Designated
    /// Dealer, but there are no enforced requirements that it be one.
    ///
    /// # Technical Description
    /// This transaction permanently destroys all the coins of `Token` type
    /// stored in the `Diem::Preburn<Token>` resource published under the
    /// `preburn_address` account address.
    ///
    /// This transaction will only succeed if the sending `account` has a
    /// `Diem::BurnCapability<Token>`, and a `Diem::Preburn<Token>` resource
    /// exists under `preburn_address`, with a non-zero `to_burn` field. After the successful execution
    /// of this transaction the `total_value` field in the
    /// `Diem::CurrencyInfo<Token>` resource published under `0xA550C18` will be
    /// decremented by the value of the `to_burn` field of the preburn resource
    /// under `preburn_address` immediately before this transaction, and the
    /// `to_burn` field of the preburn resource will have a zero value.
    ///
    /// # Events
    /// The successful execution of this transaction will emit a `Diem::BurnEvent` on the event handle
    /// held in the `Diem::CurrencyInfo<Token>` resource's `burn_events` published under
    /// `0xA550C18`.
    ///
    /// # Parameters
    /// | Name              | Type      | Description                                                                                                        |
    /// | ------            | ------    | -------------                                                                                                      |
    /// | `Token`           | Type      | The Move type for the `Token` currency being burned. `Token` must be an already-registered currency on-chain.      |
    /// | `tc_account`      | `signer`  | The signer of the sending account of this transaction, must have a burn capability for `Token` published under it. |
    /// | `sliding_nonce`   | `u64`     | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.                                         |
    /// | `preburn_address` | `address` | The address where the coins to-be-burned are currently held.                                                       |
    /// | `amount`          | `u64`     | The amount to be burned.                                                                                           |
    ///
    /// # Common Abort Conditions
    /// | Error Category                | Error Reason                            | Description                                                                                                                         |
    /// | ----------------              | --------------                          | -------------                                                                                                                       |
    /// | `Errors::NOT_PUBLISHED`       | `SlidingNonce::ESLIDING_NONCE`          | A `SlidingNonce` resource is not published under `account`.                                                                         |
    /// | `Errors::INVALID_ARGUMENT`    | `SlidingNonce::ENONCE_TOO_OLD`          | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not.                                          |
    /// | `Errors::INVALID_ARGUMENT`    | `SlidingNonce::ENONCE_TOO_NEW`          | The `sliding_nonce` is too far in the future.                                                                                       |
    /// | `Errors::INVALID_ARGUMENT`    | `SlidingNonce::ENONCE_ALREADY_RECORDED` | The `sliding_nonce` has been previously recorded.                                                                                   |
    /// | `Errors::REQUIRES_CAPABILITY` | `Diem::EBURN_CAPABILITY`                | The sending `account` does not have a `Diem::BurnCapability<Token>` published under it.                                             |
    /// | `Errors::INVALID_STATE`       | `Diem::EPREBURN_NOT_FOUND`              | The `Diem::PreburnQueue<Token>` resource under `preburn_address` does not contain a preburn request with a value matching `amount`. |
    /// | `Errors::NOT_PUBLISHED`       | `Diem::EPREBURN_QUEUE`                  | The account at `preburn_address` does not have a `Diem::PreburnQueue<Token>` resource published under it.                           |
    /// | `Errors::NOT_PUBLISHED`       | `Diem::ECURRENCY_INFO`                  | The specified `Token` is not a registered currency on-chain.                                                                        |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::burn_txn_fees`
    /// * `TreasuryComplianceScripts::cancel_burn_with_amount`
    /// * `TreasuryComplianceScripts::preburn`

    public(script) fun burn_with_amount<Token>(account: signer, sliding_nonce: u64, preburn_address: address, amount: u64) {
        SlidingNonce::record_nonce_or_abort(&account, sliding_nonce);
        Diem::burn<Token>(&account, preburn_address, amount)
    }
    spec burn_with_amount {
        use Std::Errors;
        use DiemFramework::DiemAccount;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        include SlidingNonce::RecordNonceAbortsIf{ seq_nonce: sliding_nonce };
        include Diem::BurnAbortsIf<Token>;
        include Diem::BurnEnsures<Token>;

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::REQUIRES_CAPABILITY,
            Errors::NOT_PUBLISHED,
            Errors::INVALID_STATE,
            Errors::LIMIT_EXCEEDED;

        include Diem::BurnWithResourceCapEmits<Token>{preburn: Diem::spec_make_preburn(amount)};

        /// **Access Control:**
        /// Only the account with the burn capability can burn coins [[H3]][PERMISSION].
        include Diem::AbortsIfNoBurnCapability<Token>{account: account};
    }

    /// # Summary
    /// Moves a specified number of coins in a given currency from the account's
    /// balance to its preburn area after which the coins may be burned. This
    /// transaction may be sent by any account that holds a balance and preburn area
    /// in the specified currency.
    ///
    /// # Technical Description
    /// Moves the specified `amount` of coins in `Token` currency from the sending `account`'s
    /// `DiemAccount::Balance<Token>` to the `Diem::Preburn<Token>` published under the same
    /// `account`. `account` must have both of these resources published under it at the start of this
    /// transaction in order for it to execute successfully.
    ///
    /// # Events
    /// Successful execution of this script emits two events:
    /// * `DiemAccount::SentPaymentEvent ` on `account`'s `DiemAccount::DiemAccount` `sent_events`
    /// handle with the `payee` and `payer` fields being `account`'s address; and
    /// * A `Diem::PreburnEvent` with `Token`'s currency code on the
    /// `Diem::CurrencyInfo<Token`'s `preburn_events` handle for `Token` and with
    /// `preburn_address` set to `account`'s address.
    ///
    /// # Parameters
    /// | Name      | Type     | Description                                                                                                                      |
    /// | ------    | ------   | -------------                                                                                                                    |
    /// | `Token`   | Type     | The Move type for the `Token` currency being moved to the preburn area. `Token` must be an already-registered currency on-chain. |
    /// | `account` | `signer` | The signer of the sending account.                                                                                               |
    /// | `amount`  | `u64`    | The amount in `Token` to be moved to the preburn area.                                                                           |
    ///
    /// # Common Abort Conditions
    /// | Error Category           | Error Reason                                             | Description                                                                             |
    /// | ----------------         | --------------                                           | -------------                                                                           |
    /// | `Errors::NOT_PUBLISHED`  | `Diem::ECURRENCY_INFO`                                  | The `Token` is not a registered currency on-chain.                                      |
    /// | `Errors::INVALID_STATE`  | `DiemAccount::EWITHDRAWAL_CAPABILITY_ALREADY_EXTRACTED` | The withdrawal capability for `account` has already been extracted.                     |
    /// | `Errors::LIMIT_EXCEEDED` | `DiemAccount::EINSUFFICIENT_BALANCE`                    | `amount` is greater than `payer`'s balance in `Token`.                                  |
    /// | `Errors::NOT_PUBLISHED`  | `DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY`              | `account` doesn't hold a balance in `Token`.                                            |
    /// | `Errors::NOT_PUBLISHED`  | `Diem::EPREBURN`                                        | `account` doesn't have a `Diem::Preburn<Token>` resource published under it.           |
    /// | `Errors::INVALID_STATE`  | `Diem::EPREBURN_OCCUPIED`                               | The `value` field in the `Diem::Preburn<Token>` resource under the sender is non-zero. |
    /// | `Errors::NOT_PUBLISHED`  | `Roles::EROLE_ID`                                        | The `account` did not have a role assigned to it.                                       |
    /// | `Errors::REQUIRES_ROLE`  | `Roles::EDESIGNATED_DEALER`                              | The `account` did not have the role of DesignatedDealer.                                |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::cancel_burn_with_amount`
    /// * `TreasuryComplianceScripts::burn_with_amount`
    /// * `TreasuryComplianceScripts::burn_txn_fees`

    public(script) fun preburn<Token>(account: signer, amount: u64) {
        let withdraw_cap = DiemAccount::extract_withdraw_capability(&account);
        DiemAccount::preburn<Token>(&account, &withdraw_cap, amount);
        DiemAccount::restore_withdraw_capability(withdraw_cap);
    }

    spec preburn {
        use Std::Errors;
        use Std::Signer;
        use DiemFramework::Diem;

        include DiemAccount::TransactionChecks{sender: account}; // properties checked by the prologue.
        let account_addr = Signer::spec_address_of(account);
        let cap = DiemAccount::spec_get_withdraw_cap(account_addr);
        include DiemAccount::ExtractWithdrawCapAbortsIf{sender_addr: account_addr};
        include DiemAccount::PreburnAbortsIf<Token>{dd: account, cap: cap};
        include DiemAccount::PreburnEnsures<Token>{dd: account, payer: account_addr};

        include DiemAccount::PreburnEmits<Token>{dd: account, cap: cap};

        aborts_with [check]
            Errors::NOT_PUBLISHED,
            Errors::INVALID_STATE,
            Errors::REQUIRES_ROLE,
            Errors::LIMIT_EXCEEDED;

        /// **Access Control:**
        /// Only the account with a Preburn resource or PreburnQueue resource can preburn [[H4]][PERMISSION].
        aborts_if !(exists<Diem::Preburn<Token>>(account_addr) || exists<Diem::PreburnQueue<Token>>(account_addr));
    }

    /// # Summary
    /// Burns the transaction fees collected in the `CoinType` currency so that the
    /// Diem association may reclaim the backing coins off-chain. May only be sent
    /// by the Treasury Compliance account.
    ///
    /// # Technical Description
    /// Burns the transaction fees collected in `CoinType` so that the
    /// association may reclaim the backing coins. Once this transaction has executed
    /// successfully all transaction fees that will have been collected in
    /// `CoinType` since the last time this script was called with that specific
    /// currency. Both `balance` and `preburn` fields in the
    /// `TransactionFee::TransactionFee<CoinType>` resource published under the `0xB1E55ED`
    /// account address will have a value of 0 after the successful execution of this script.
    ///
    /// # Events
    /// The successful execution of this transaction will emit a `Diem::BurnEvent` on the event handle
    /// held in the `Diem::CurrencyInfo<CoinType>` resource's `burn_events` published under
    /// `0xA550C18`.
    ///
    /// # Parameters
    /// | Name         | Type     | Description                                                                                                                                         |
    /// | ------       | ------   | -------------                                                                                                                                       |
    /// | `CoinType`   | Type     | The Move type for the `CoinType` being added to the sending account of the transaction. `CoinType` must be an already-registered currency on-chain. |
    /// | `tc_account` | `signer` | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                     |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                          | Description                                                 |
    /// | ----------------           | --------------                        | -------------                                               |
    /// | `Errors::REQUIRES_ADDRESS` | `CoreAddresses::ETREASURY_COMPLIANCE` | The sending account is not the Treasury Compliance account. |
    /// | `Errors::NOT_PUBLISHED`    | `TransactionFee::ETRANSACTION_FEE`    | `CoinType` is not an accepted transaction fee currency.     |
    /// | `Errors::INVALID_ARGUMENT` | `Diem::ECOIN`                        | The collected fees in `CoinType` are zero.                  |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::burn_with_amount`
    /// * `TreasuryComplianceScripts::cancel_burn_with_amount`

    public(script) fun burn_txn_fees<CoinType>(tc_account: signer) {
        TransactionFee::burn_fees<CoinType>(&tc_account);
    }

    /// # Summary
    /// Mints a specified number of coins in a currency to a Designated Dealer. The sending account
    /// must be the Treasury Compliance account, and coins can only be minted to a Designated Dealer
    /// account.
    ///
    /// # Technical Description
    /// Mints `mint_amount` of coins in the `CoinType` currency to Designated Dealer account at
    /// `designated_dealer_address`. The `tier_index` parameter specifies which tier should be used to
    /// check verify the off-chain approval policy, and is based in part on the on-chain tier values
    /// for the specific Designated Dealer, and the number of `CoinType` coins that have been minted to
    /// the dealer over the past 24 hours. Every Designated Dealer has 4 tiers for each currency that
    /// they support. The sending `tc_account` must be the Treasury Compliance account, and the
    /// receiver an authorized Designated Dealer account.
    ///
    /// # Events
    /// Successful execution of the transaction will emit two events:
    /// * A `Diem::MintEvent` with the amount and currency code minted is emitted on the
    /// `mint_event_handle` in the stored `Diem::CurrencyInfo<CoinType>` resource stored under
    /// `0xA550C18`; and
    /// * A `DesignatedDealer::ReceivedMintEvent` with the amount, currency code, and Designated
    /// Dealer's address is emitted on the `mint_event_handle` in the stored `DesignatedDealer::Dealer`
    /// resource published under the `designated_dealer_address`.
    ///
    /// # Parameters
    /// | Name                        | Type      | Description                                                                                                |
    /// | ------                      | ------    | -------------                                                                                              |
    /// | `CoinType`                  | Type      | The Move type for the `CoinType` being minted. `CoinType` must be an already-registered currency on-chain. |
    /// | `tc_account`                | `signer`  | The signer of the sending account of this transaction. Must be the Treasury Compliance account.            |
    /// | `sliding_nonce`             | `u64`     | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.                                 |
    /// | `designated_dealer_address` | `address` | The address of the Designated Dealer account being minted to.                                              |
    /// | `mint_amount`               | `u64`     | The number of coins to be minted.                                                                          |
    /// | `tier_index`                | `u64`     | [Deprecated] The mint tier index to use for the Designated Dealer account. Will be ignored                 |
    ///
    /// # Common Abort Conditions
    /// | Error Category                | Error Reason                                 | Description                                                                                                                  |
    /// | ----------------              | --------------                               | -------------                                                                                                                |
    /// | `Errors::NOT_PUBLISHED`       | `SlidingNonce::ESLIDING_NONCE`               | A `SlidingNonce` resource is not published under `tc_account`.                                                               |
    /// | `Errors::INVALID_ARGUMENT`    | `SlidingNonce::ENONCE_TOO_OLD`               | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not.                                   |
    /// | `Errors::INVALID_ARGUMENT`    | `SlidingNonce::ENONCE_TOO_NEW`               | The `sliding_nonce` is too far in the future.                                                                                |
    /// | `Errors::INVALID_ARGUMENT`    | `SlidingNonce::ENONCE_ALREADY_RECORDED`      | The `sliding_nonce` has been previously recorded.                                                                            |
    /// | `Errors::REQUIRES_ADDRESS`    | `CoreAddresses::ETREASURY_COMPLIANCE`        | `tc_account` is not the Treasury Compliance account.                                                                         |
    /// | `Errors::REQUIRES_ROLE`       | `Roles::ETREASURY_COMPLIANCE`                | `tc_account` is not the Treasury Compliance account.                                                                         |
    /// | `Errors::INVALID_ARGUMENT`    | `DesignatedDealer::EINVALID_MINT_AMOUNT`     | `mint_amount` is zero.                                                                                                       |
    /// | `Errors::NOT_PUBLISHED`       | `DesignatedDealer::EDEALER`                  | `DesignatedDealer::Dealer` or `DesignatedDealer::TierInfo<CoinType>` resource does not exist at `designated_dealer_address`. |
    /// | `Errors::REQUIRES_CAPABILITY` | `Diem::EMINT_CAPABILITY`                    | `tc_account` does not have a `Diem::MintCapability<CoinType>` resource published under it.                                  |
    /// | `Errors::INVALID_STATE`       | `Diem::EMINTING_NOT_ALLOWED`                | Minting is not currently allowed for `CoinType` coins.                                                                       |
    /// | `Errors::LIMIT_EXCEEDED`      | `DiemAccount::EDEPOSIT_EXCEEDS_LIMITS`      | The depositing of the funds would exceed the `account`'s account limits.                                                     |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_designated_dealer`
    /// * `PaymentScripts::peer_to_peer_with_metadata`
    /// * `AccountAdministrationScripts::rotate_dual_attestation_info`

    public(script) fun tiered_mint<CoinType>(
        tc_account: signer,
        sliding_nonce: u64,
        designated_dealer_address: address,
        mint_amount: u64,
        tier_index: u64
    ) {
        SlidingNonce::record_nonce_or_abort(&tc_account, sliding_nonce);
        DiemAccount::tiered_mint<CoinType>(
            &tc_account, designated_dealer_address, mint_amount, tier_index
        );
    }

    spec tiered_mint {
        use Std::Errors;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: tc_account}; // properties checked by the prologue.
        include SlidingNonce::RecordNonceAbortsIf{account: tc_account, seq_nonce: sliding_nonce};
        include DiemAccount::TieredMintAbortsIf<CoinType>;
        include DiemAccount::TieredMintEnsures<CoinType>;

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::REQUIRES_ADDRESS,
            Errors::NOT_PUBLISHED,
            Errors::REQUIRES_CAPABILITY,
            Errors::INVALID_STATE,
            Errors::LIMIT_EXCEEDED,
            Errors::REQUIRES_ROLE;

        include DiemAccount::TieredMintEmits<CoinType>;

        /// **Access Control:**
        /// Only the Treasury Compliance account can mint [[H1]][PERMISSION].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
    }

    /// # Summary
    /// Freezes the account at `address`. The sending account of this transaction
    /// must be the Treasury Compliance account. The account being frozen cannot be
    /// the Diem Root or Treasury Compliance account. After the successful
    /// execution of this transaction no transactions may be sent from the frozen
    /// account, and the frozen account may not send or receive coins.
    ///
    /// # Technical Description
    /// Sets the `AccountFreezing::FreezingBit` to `true` and emits a
    /// `AccountFreezing::FreezeAccountEvent`. The transaction sender must be the
    /// Treasury Compliance account, but the account at `to_freeze_account` must
    /// not be either `0xA550C18` (the Diem Root address), or `0xB1E55ED` (the
    /// Treasury Compliance address). Note that this is a per-account property
    /// e.g., freezing a Parent VASP will not effect the status any of its child
    /// accounts and vice versa.
    ///
    ///
    /// # Events
    /// Successful execution of this transaction will emit a `AccountFreezing::FreezeAccountEvent` on
    /// the `freeze_event_handle` held in the `AccountFreezing::FreezeEventsHolder` resource published
    /// under `0xA550C18` with the `frozen_address` being the `to_freeze_account`.
    ///
    /// # Parameters
    /// | Name                | Type      | Description                                                                                     |
    /// | ------              | ------    | -------------                                                                                   |
    /// | `tc_account`        | `signer`  | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
    /// | `sliding_nonce`     | `u64`     | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.                      |
    /// | `to_freeze_account` | `address` | The account address to be frozen.                                                               |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                 | Description                                                                                |
    /// | ----------------           | --------------                               | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`    | `SlidingNonce::ESLIDING_NONCE`               | A `SlidingNonce` resource is not published under `tc_account`.                             |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_OLD`               | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_NEW`               | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_ALREADY_RECORDED`      | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::REQUIRES_ADDRESS` | `CoreAddresses::ETREASURY_COMPLIANCE`        | The sending account is not the Treasury Compliance account.                                |
    /// | `Errors::REQUIRES_ROLE`    | `Roles::ETREASURY_COMPLIANCE`                | The sending account is not the Treasury Compliance account.                                |
    /// | `Errors::INVALID_ARGUMENT` | `AccountFreezing::ECANNOT_FREEZE_TC`         | `to_freeze_account` was the Treasury Compliance account (`0xB1E55ED`).                     |
    /// | `Errors::INVALID_ARGUMENT` | `AccountFreezing::ECANNOT_FREEZE_DIEM_ROOT` | `to_freeze_account` was the Diem Root account (`0xA550C18`).                              |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::unfreeze_account`

    public(script) fun freeze_account(tc_account: signer, sliding_nonce: u64, to_freeze_account: address) {
        SlidingNonce::record_nonce_or_abort(&tc_account, sliding_nonce);
        AccountFreezing::freeze_account(&tc_account, to_freeze_account);
    }

    /// # Summary
    /// Unfreezes the account at `address`. The sending account of this transaction must be the
    /// Treasury Compliance account. After the successful execution of this transaction transactions
    /// may be sent from the previously frozen account, and coins may be sent and received.
    ///
    /// # Technical Description
    /// Sets the `AccountFreezing::FreezingBit` to `false` and emits a
    /// `AccountFreezing::UnFreezeAccountEvent`. The transaction sender must be the Treasury Compliance
    /// account. Note that this is a per-account property so unfreezing a Parent VASP will not effect
    /// the status any of its child accounts and vice versa.
    ///
    /// # Events
    /// Successful execution of this script will emit a `AccountFreezing::UnFreezeAccountEvent` with
    /// the `unfrozen_address` set the `to_unfreeze_account`'s address.
    ///
    /// # Parameters
    /// | Name                  | Type      | Description                                                                                     |
    /// | ------                | ------    | -------------                                                                                   |
    /// | `tc_account`          | `signer`  | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
    /// | `sliding_nonce`       | `u64`     | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.                      |
    /// | `to_unfreeze_account` | `address` | The account address to be frozen.                                                               |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                            | Description                                                                                |
    /// | ----------------           | --------------                          | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`    | `SlidingNonce::ESLIDING_NONCE`          | A `SlidingNonce` resource is not published under `account`.                                |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_OLD`          | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_NEW`          | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_ALREADY_RECORDED` | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::REQUIRES_ADDRESS` | `CoreAddresses::ETREASURY_COMPLIANCE`   | The sending account is not the Treasury Compliance account.                                |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::freeze_account`

    public(script) fun unfreeze_account(account: signer, sliding_nonce: u64, to_unfreeze_account: address) {
        SlidingNonce::record_nonce_or_abort(&account, sliding_nonce);
        AccountFreezing::unfreeze_account(&account, to_unfreeze_account);
    }

    /// # Summary
    /// Update the dual attestation limit on-chain. Defined in terms of micro-XDX.  The transaction can
    /// only be sent by the Treasury Compliance account.  After this transaction all inter-VASP
    /// payments over this limit must be checked for dual attestation.
    ///
    /// # Technical Description
    /// Updates the `micro_xdx_limit` field of the `DualAttestation::Limit` resource published under
    /// `0xA550C18`. The amount is set in micro-XDX.
    ///
    /// # Parameters
    /// | Name                  | Type     | Description                                                                                     |
    /// | ------                | ------   | -------------                                                                                   |
    /// | `tc_account`          | `signer` | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
    /// | `sliding_nonce`       | `u64`    | The `sliding_nonce` (see: `SlidingNonce`) to be used for this transaction.                      |
    /// | `new_micro_xdx_limit` | `u64`    | The new dual attestation limit to be used on-chain.                                             |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                            | Description                                                                                |
    /// | ----------------           | --------------                          | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`    | `SlidingNonce::ESLIDING_NONCE`          | A `SlidingNonce` resource is not published under `tc_account`.                             |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_OLD`          | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_NEW`          | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_ALREADY_RECORDED` | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::REQUIRES_ADDRESS` | `CoreAddresses::ETREASURY_COMPLIANCE`   | `tc_account` is not the Treasury Compliance account.                                       |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::update_exchange_rate`
    /// * `TreasuryComplianceScripts::update_minting_ability`

    public(script) fun update_dual_attestation_limit(
            tc_account: signer,
            sliding_nonce: u64,
            new_micro_xdx_limit: u64
        ) {
        SlidingNonce::record_nonce_or_abort(&tc_account, sliding_nonce);
        DualAttestation::set_microdiem_limit(&tc_account, new_micro_xdx_limit);
    }

    /// # Summary
    /// Update the rough on-chain exchange rate between a specified currency and XDX (as a conversion
    /// to micro-XDX). The transaction can only be sent by the Treasury Compliance account. After this
    /// transaction the updated exchange rate will be used for normalization of gas prices, and for
    /// dual attestation checking.
    ///
    /// # Technical Description
    /// Updates the on-chain exchange rate from the given `Currency` to micro-XDX.  The exchange rate
    /// is given by `new_exchange_rate_numerator/new_exchange_rate_denominator`.
    ///
    /// # Parameters
    /// | Name                            | Type     | Description                                                                                                                        |
    /// | ------                          | ------   | -------------                                                                                                                      |
    /// | `Currency`                      | Type     | The Move type for the `Currency` whose exchange rate is being updated. `Currency` must be an already-registered currency on-chain. |
    /// | `tc_account`                    | `signer` | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                    |
    /// | `sliding_nonce`                 | `u64`    | The `sliding_nonce` (see: `SlidingNonce`) to be used for the transaction.                                                          |
    /// | `new_exchange_rate_numerator`   | `u64`    | The numerator for the new to micro-XDX exchange rate for `Currency`.                                                               |
    /// | `new_exchange_rate_denominator` | `u64`    | The denominator for the new to micro-XDX exchange rate for `Currency`.                                                             |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                            | Description                                                                                |
    /// | ----------------           | --------------                          | -------------                                                                              |
    /// | `Errors::NOT_PUBLISHED`    | `SlidingNonce::ESLIDING_NONCE`          | A `SlidingNonce` resource is not published under `tc_account`.                             |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_OLD`          | The `sliding_nonce` is too old and it's impossible to determine if it's duplicated or not. |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_TOO_NEW`          | The `sliding_nonce` is too far in the future.                                              |
    /// | `Errors::INVALID_ARGUMENT` | `SlidingNonce::ENONCE_ALREADY_RECORDED` | The `sliding_nonce` has been previously recorded.                                          |
    /// | `Errors::REQUIRES_ADDRESS` | `CoreAddresses::ETREASURY_COMPLIANCE`   | `tc_account` is not the Treasury Compliance account.                                       |
    /// | `Errors::REQUIRES_ROLE`    | `Roles::ETREASURY_COMPLIANCE`           | `tc_account` is not the Treasury Compliance account.                                       |
    /// | `Errors::INVALID_ARGUMENT` | `FixedPoint32::EDENOMINATOR`            | `new_exchange_rate_denominator` is zero.                                                   |
    /// | `Errors::INVALID_ARGUMENT` | `FixedPoint32::ERATIO_OUT_OF_RANGE`     | The quotient is unrepresentable as a `FixedPoint32`.                                       |
    /// | `Errors::LIMIT_EXCEEDED`   | `FixedPoint32::ERATIO_OUT_OF_RANGE`     | The quotient is unrepresentable as a `FixedPoint32`.                                       |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::update_dual_attestation_limit`
    /// * `TreasuryComplianceScripts::update_minting_ability`

    public(script) fun update_exchange_rate<Currency>(
            tc_account: signer,
            sliding_nonce: u64,
            new_exchange_rate_numerator: u64,
            new_exchange_rate_denominator: u64,
    ) {
        SlidingNonce::record_nonce_or_abort(&tc_account, sliding_nonce);
        let rate = FixedPoint32::create_from_rational(
                new_exchange_rate_numerator,
                new_exchange_rate_denominator,
        );
        Diem::update_xdx_exchange_rate<Currency>(&tc_account, rate);
    }
    spec update_exchange_rate {
        use Std::Errors;
        use DiemFramework::DiemAccount;
        use DiemFramework::Roles;

        include DiemAccount::TransactionChecks{sender: tc_account}; // properties checked by the prologue.
        include SlidingNonce::RecordNonceAbortsIf{ account: tc_account, seq_nonce: sliding_nonce };
        include FixedPoint32::CreateFromRationalAbortsIf{
               numerator: new_exchange_rate_numerator,
               denominator: new_exchange_rate_denominator
        };
        let rate = FixedPoint32::spec_create_from_rational(
                new_exchange_rate_numerator,
                new_exchange_rate_denominator
        );
        include Diem::UpdateXDXExchangeRateAbortsIf<Currency>;
        include Diem::UpdateXDXExchangeRateEnsures<Currency>{xdx_exchange_rate: rate};
        include Diem::UpdateXDXExchangeRateEmits<Currency>{xdx_exchange_rate: rate};

        aborts_with [check]
            Errors::INVALID_ARGUMENT,
            Errors::REQUIRES_ADDRESS,
            Errors::LIMIT_EXCEEDED,
            Errors::REQUIRES_ROLE,
            Errors::NOT_PUBLISHED;

        /// **Access Control:**
        /// Only the Treasury Compliance account can update the exchange rate [[H5]][PERMISSION].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
    }

    /// # Summary
    /// Script to allow or disallow minting of new coins in a specified currency.  This transaction can
    /// only be sent by the Treasury Compliance account.  Turning minting off for a currency will have
    /// no effect on coins already in circulation, and coins may still be removed from the system.
    ///
    /// # Technical Description
    /// This transaction sets the `can_mint` field of the `Diem::CurrencyInfo<Currency>` resource
    /// published under `0xA550C18` to the value of `allow_minting`. Minting of coins if allowed if
    /// this field is set to `true` and minting of new coins in `Currency` is disallowed otherwise.
    /// This transaction needs to be sent by the Treasury Compliance account.
    ///
    /// # Parameters
    /// | Name            | Type     | Description                                                                                                                          |
    /// | ------          | ------   | -------------                                                                                                                        |
    /// | `Currency`      | Type     | The Move type for the `Currency` whose minting ability is being updated. `Currency` must be an already-registered currency on-chain. |
    /// | `account`       | `signer` | Signer of the sending account. Must be the Diem Root account.                                                                        |
    /// | `allow_minting` | `bool`   | Whether to allow minting of new coins in `Currency`.                                                                                 |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                          | Description                                          |
    /// | ----------------           | --------------                        | -------------                                        |
    /// | `Errors::REQUIRES_ADDRESS` | `CoreAddresses::ETREASURY_COMPLIANCE` | `tc_account` is not the Treasury Compliance account. |
    /// | `Errors::NOT_PUBLISHED`    | `Diem::ECURRENCY_INFO`               | `Currency` is not a registered currency on-chain.    |
    ///
    /// # Related Scripts
    /// * `TreasuryComplianceScripts::update_dual_attestation_limit`
    /// * `TreasuryComplianceScripts::update_exchange_rate`

    public(script) fun update_minting_ability<Currency>(
        tc_account: signer,
        allow_minting: bool
    ) {
        Diem::update_minting_ability<Currency>(&tc_account, allow_minting);
    }

    /// # Summary
    /// Add a VASP domain to parent VASP account. The transaction can only be sent by
    /// the Treasury Compliance account.
    ///
    /// # Technical Description
    /// Adds a `VASPDomain::VASPDomain` to the `domains` field of the `VASPDomain::VASPDomains` resource published under
    /// the account at `address`.
    ///
    /// # Parameters
    /// | Name         | Type         | Description                                                                                     |
    /// | ------       | ------       | -------------                                                                                   |
    /// | `tc_account` | `signer`     | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
    /// | `address`    | `address`    | The `address` of the parent VASP account that will have have `domain` added to its domains.     |
    /// | `domain`     | `vector<u8>` | The domain to be added.                                                                         |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                             | Description                                                                                                                            |
    /// | ----------------           | --------------                           | -------------                                                                                                                          |
    /// | `Errors::REQUIRES_ROLE`    | `Roles::ETREASURY_COMPLIANCE`            | The sending account is not the Treasury Compliance account.                                                                            |
    /// | `Errors::REQUIRES_ADDRESS` | `CoreAddresses::ETREASURY_COMPLIANCE`    | `tc_account` is not the Treasury Compliance account.                                                                                   |
    /// | `Errors::NOT_PUBLISHED`    | `VASPDomain::EVASP_DOMAIN_MANAGER`        | The `VASPDomain::VASPDomainManager` resource is not yet published under the Treasury Compliance account.                                 |
    /// | `Errors::NOT_PUBLISHED`    | `VASPDomain::EVASP_DOMAINS_NOT_PUBLISHED` | `address` does not have a `VASPDomain::VASPDomains` resource published under it.                                                         |
    /// | `Errors::INVALID_ARGUMENT` | `VASPDomain::EDOMAIN_ALREADY_EXISTS`         | The `domain` already exists in the list of `VASPDomain::VASPDomain`s  in the `VASPDomain::VASPDomains` resource published under `address`. |
    /// | `Errors::INVALID_ARGUMENT` | `VASPDomain::EINVALID_VASP_DOMAIN`        | The `domain` is greater in length than `VASPDomain::DOMAIN_LENGTH`.                                                                        |
    public(script) fun add_vasp_domain (
        tc_account: signer,
        address: address,
        domain: vector<u8>,
    ) {
        VASPDomain::add_vasp_domain(&tc_account, address, domain);
    }
    spec add_vasp_domain {
        use Std::Errors;
        include DiemAccount::TransactionChecks{sender: tc_account}; // properties checked by the prologue.
        include VASPDomain::AddVASPDomainAbortsIf;
        include VASPDomain::AddVASPDomainEnsures;
        include VASPDomain::AddVASPDomainEmits;
        aborts_with [check]
            Errors::REQUIRES_ROLE,
            Errors::REQUIRES_ADDRESS,
            Errors::NOT_PUBLISHED,
            Errors::INVALID_ARGUMENT;
    }

    /// # Summary
    /// Remove a VASP domain from parent VASP account. The transaction can only be sent by
    /// the Treasury Compliance account.
    ///
    /// # Technical Description
    /// Removes a `VASPDomain::VASPDomain` from the `domains` field of the `VASPDomain::VASPDomains` resource published under
    /// account with `address`.
    ///
    /// # Parameters
    /// | Name         | Type         | Description                                                                                     |
    /// | ------       | ------       | -------------                                                                                   |
    /// | `tc_account` | `signer`     | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
    /// | `address`    | `address`    | The `address` of parent VASP account that will update its domains.                              |
    /// | `domain`     | `vector<u8>` | The domain name.                                                                                |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                             | Description                                                                                                                            |
    /// | ----------------           | --------------                           | -------------                                                                                                                          |
    /// | `Errors::REQUIRES_ROLE`    | `Roles::ETREASURY_COMPLIANCE`            | The sending account is not the Treasury Compliance account.                                                                            |
    /// | `Errors::REQUIRES_ADDRESS` | `CoreAddresses::ETREASURY_COMPLIANCE`    | `tc_account` is not the Treasury Compliance account.                                                                                   |
    /// | `Errors::NOT_PUBLISHED`    | `VASPDomain::EVASP_DOMAIN_MANAGER`        | The `VASPDomain::VASPDomainManager` resource is not yet published under the Treasury Compliance account.                                 |
    /// | `Errors::NOT_PUBLISHED`    | `VASPDomain::EVASP_DOMAINS_NOT_PUBLISHED` | `address` does not have a `VASPDomain::VASPDomains` resource published under it.                                                         |
    /// | `Errors::INVALID_ARGUMENT` | `VASPDomain::EINVALID_VASP_DOMAIN`        | The `domain` is greater in length than `VASPDomain::DOMAIN_LENGTH`.                                                                        |
    /// | `Errors::INVALID_ARGUMENT` | `VASPDomain::EVASP_DOMAIN_NOT_FOUND`              | The `domain` does not exist in the list of `VASPDomain::VASPDomain`s  in the `VASPDomain::VASPDomains` resource published under `address`. |
    public(script) fun remove_vasp_domain (
        tc_account: signer,
        address: address,
        domain: vector<u8>,
    ) {
        VASPDomain::remove_vasp_domain(&tc_account, address, domain);
    }
    spec remove_vasp_domain {
        use Std::Errors;
        aborts_with [check]
            Errors::REQUIRES_ROLE,
            Errors::REQUIRES_ADDRESS,
            Errors::NOT_PUBLISHED,
            Errors::INVALID_ARGUMENT;
    }
}
