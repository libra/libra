/// This module holds all payment related script entrypoints in the Diem Framework.
/// Any account that can hold a balance can use the transaction scripts within this module.
module DiemFramework::PaymentScripts {
    use DiemFramework::DiemAccount;
    use DiemFramework::DualAttestation;
    use Std::Signer;

    /// # Summary
    /// Transfers a given number of coins in a specified currency from one account to another.
    /// Transfers over a specified amount defined on-chain that are between two different VASPs, or
    /// other accounts that have opted-in will be subject to on-chain checks to ensure the receiver has
    /// agreed to receive the coins.  This transaction can be sent by any account that can hold a
    /// balance, and to any account that can hold a balance. Both accounts must hold balances in the
    /// currency being transacted.
    ///
    /// # Technical Description
    ///
    /// Transfers `amount` coins of type `Currency` from `payer` to `payee` with (optional) associated
    /// `metadata` and an (optional) `metadata_signature` on the message of the form
    /// `metadata` | `Signer::address_of(payer)` | `amount` | `DualAttestation::DOMAIN_SEPARATOR`, that
    /// has been signed by the `payee`'s private key associated with the `compliance_public_key` held in
    /// the `payee`'s `DualAttestation::Credential`. Both the `Signer::address_of(payer)` and `amount` fields
    /// in the `metadata_signature` must be BCS-encoded bytes, and `|` denotes concatenation.
    /// The `metadata` and `metadata_signature` parameters are only required if `amount` >=
    /// `DualAttestation::get_cur_microdiem_limit` XDX and `payer` and `payee` are distinct VASPs.
    /// However, a transaction sender can opt in to dual attestation even when it is not required
    /// (e.g., a DesignatedDealer -> VASP payment) by providing a non-empty `metadata_signature`.
    /// Standardized `metadata` BCS format can be found in `diem_types::transaction::metadata::Metadata`.
    ///
    /// # Events
    /// Successful execution of this script emits two events:
    /// * A `DiemAccount::SentPaymentEvent` on `payer`'s `DiemAccount::DiemAccount` `sent_events` handle; and
    /// * A `DiemAccount::ReceivedPaymentEvent` on `payee`'s `DiemAccount::DiemAccount` `received_events` handle.
    ///
    /// # Parameters
    /// | Name                 | Type         | Description                                                                                                                  |
    /// | ------               | ------       | -------------                                                                                                                |
    /// | `Currency`           | Type         | The Move type for the `Currency` being sent in this transaction. `Currency` must be an already-registered currency on-chain. |
    /// | `payer`              | `signer`     | The signer of the sending account that coins are being transferred from.                                                     |
    /// | `payee`              | `address`    | The address of the account the coins are being transferred to.                                                               |
    /// | `metadata`           | `vector<u8>` | Optional metadata about this payment.                                                                                        |
    /// | `metadata_signature` | `vector<u8>` | Optional signature over `metadata` and payment information. See                                                              |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                     | Description                                                                                                                         |
    /// | ----------------           | --------------                                   | -------------                                                                                                                       |
    /// | `Errors::NOT_PUBLISHED`    | `DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY`       | `payer` doesn't hold a balance in `Currency`.                                                                                       |
    /// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EINSUFFICIENT_BALANCE`             | `amount` is greater than `payer`'s balance in `Currency`.                                                                           |
    /// | `Errors::INVALID_ARGUMENT` | `DiemAccount::ECOIN_DEPOSIT_IS_ZERO`             | `amount` is zero.                                                                                                                   |
    /// | `Errors::NOT_PUBLISHED`    | `DiemAccount::EPAYEE_DOES_NOT_EXIST`             | No account exists at the `payee` address.                                                                                           |
    /// | `Errors::INVALID_ARGUMENT` | `DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE`  | An account exists at `payee`, but it does not accept payments in `Currency`.                                                        |
    /// | `Errors::INVALID_STATE`    | `AccountFreezing::EACCOUNT_FROZEN`               | The `payee` account is frozen.                                                                                                      |
    /// | `Errors::INVALID_ARGUMENT` | `DualAttestation::EMALFORMED_METADATA_SIGNATURE` | `metadata_signature` is not 64 bytes.                                                                                               |
    /// | `Errors::INVALID_ARGUMENT` | `DualAttestation::EINVALID_METADATA_SIGNATURE`   | `metadata_signature` does not verify on the against the `payee'`s `DualAttestation::Credential` `compliance_public_key` public key. |
    /// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EWITHDRAWAL_EXCEEDS_LIMITS`        | `payer` has exceeded its daily withdrawal limits for the backing coins of XDX.                                                      |
    /// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EDEPOSIT_EXCEEDS_LIMITS`           | `payee` has exceeded its daily deposit limits for XDX.                                                                              |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_child_vasp_account`
    /// * `AccountCreationScripts::create_parent_vasp_account`
    /// * `AccountAdministrationScripts::add_currency_to_account`
    /// * `PaymentScripts::peer_to_peer_by_signers`
    public(script) fun peer_to_peer_with_metadata<Currency>(
        payer: signer,
        payee: address,
        amount: u64,
        metadata: vector<u8>,
        metadata_signature: vector<u8>
    ) {
        let payer_withdrawal_cap = DiemAccount::extract_withdraw_capability(&payer);
        DiemAccount::pay_from<Currency>(
            &payer_withdrawal_cap, payee, amount, metadata, metadata_signature
        );
        DiemAccount::restore_withdraw_capability(payer_withdrawal_cap);
    }

    /// # Summary
    /// Transfers a given number of coins in a specified currency from one account to another by multi-agent transaction.
    /// Transfers over a specified amount defined on-chain that are between two different VASPs, or
    /// other accounts that have opted-in will be subject to on-chain checks to ensure the receiver has
    /// agreed to receive the coins.  This transaction can be sent by any account that can hold a
    /// balance, and to any account that can hold a balance. Both accounts must hold balances in the
    /// currency being transacted.
    ///
    /// # Technical Description
    ///
    /// Transfers `amount` coins of type `Currency` from `payer` to `payee` with (optional) associated
    /// `metadata`.
    /// Dual attestation is not applied to this script as payee is also a signer of the transaction.
    /// Standardized `metadata` BCS format can be found in `diem_types::transaction::metadata::Metadata`.
    ///
    /// # Events
    /// Successful execution of this script emits two events:
    /// * A `DiemAccount::SentPaymentEvent` on `payer`'s `DiemAccount::DiemAccount` `sent_events` handle; and
    /// * A `DiemAccount::ReceivedPaymentEvent` on `payee`'s `DiemAccount::DiemAccount` `received_events` handle.
    ///
    /// # Parameters
    /// | Name                 | Type         | Description                                                                                                                  |
    /// | ------               | ------       | -------------                                                                                                                |
    /// | `Currency`           | Type         | The Move type for the `Currency` being sent in this transaction. `Currency` must be an already-registered currency on-chain. |
    /// | `payer`              | `signer`     | The signer of the sending account that coins are being transferred from.                                                     |
    /// | `payee`              | `signer`     | The signer of the receiving account that the coins are being transferred to.                                                 |
    /// | `metadata`           | `vector<u8>` | Optional metadata about this payment.                                                                                        |
    ///
    /// # Common Abort Conditions
    /// | Error Category             | Error Reason                                     | Description                                                                                                                         |
    /// | ----------------           | --------------                                   | -------------                                                                                                                       |
    /// | `Errors::NOT_PUBLISHED`    | `DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY`       | `payer` doesn't hold a balance in `Currency`.                                                                                       |
    /// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EINSUFFICIENT_BALANCE`             | `amount` is greater than `payer`'s balance in `Currency`.                                                                           |
    /// | `Errors::INVALID_ARGUMENT` | `DiemAccount::ECOIN_DEPOSIT_IS_ZERO`             | `amount` is zero.                                                                                                                   |
    /// | `Errors::NOT_PUBLISHED`    | `DiemAccount::EPAYEE_DOES_NOT_EXIST`             | No account exists at the `payee` address.                                                                                           |
    /// | `Errors::INVALID_ARGUMENT` | `DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE`  | An account exists at `payee`, but it does not accept payments in `Currency`.                                                        |
    /// | `Errors::INVALID_STATE`    | `AccountFreezing::EACCOUNT_FROZEN`               | The `payee` account is frozen.                                                                                                      |
    /// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EWITHDRAWAL_EXCEEDS_LIMITS`        | `payer` has exceeded its daily withdrawal limits for the backing coins of XDX.                                                      |
    /// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EDEPOSIT_EXCEEDS_LIMITS`           | `payee` has exceeded its daily deposit limits for XDX.                                                                              |
    ///
    /// # Related Scripts
    /// * `AccountCreationScripts::create_child_vasp_account`
    /// * `AccountCreationScripts::create_parent_vasp_account`
    /// * `AccountAdministrationScripts::add_currency_to_account`
    /// * `PaymentScripts::peer_to_peer_with_metadata`
    public(script) fun peer_to_peer_by_signers<Currency>(
        payer: signer,
        payee: signer,
        amount: u64,
        metadata: vector<u8>,
    ) {
        let payer_withdrawal_cap = DiemAccount::extract_withdraw_capability(&payer);
        DiemAccount::pay_by_signers<Currency>(
            &payer_withdrawal_cap, &payee, amount, metadata
        );
        DiemAccount::restore_withdraw_capability(payer_withdrawal_cap);
    }

    spec peer_to_peer_with_metadata {
        include PeerToPeer<Currency>;
        include DualAttestation::AssertPaymentOkAbortsIf<Currency>{
            payer: Signer::spec_address_of(payer),
            value: amount
        };
    }

    spec peer_to_peer_by_signers {
        include PeerToPeer<Currency>{payee: Signer::spec_address_of(payee)};
    }

    spec schema PeerToPeer<Currency> {
        use Std::Errors;

        payer: signer;
        payee: address;
        amount: u64;
        metadata: vector<u8>;

        include DiemAccount::TransactionChecks{sender: payer}; // properties checked by the prologue.
        let payer_addr = Signer::spec_address_of(payer);
        let cap = DiemAccount::spec_get_withdraw_cap(payer_addr);
        include DiemAccount::ExtractWithdrawCapAbortsIf{sender_addr: payer_addr};
        include DiemAccount::PayFromAbortsIf<Currency>{cap: cap};

        /// The balances of payer and payee change by the correct amount.
        ensures payer_addr != payee
            ==> DiemAccount::balance<Currency>(payer_addr)
            == old(DiemAccount::balance<Currency>(payer_addr)) - amount;
        ensures payer_addr != payee
            ==> DiemAccount::balance<Currency>(payee)
            == old(DiemAccount::balance<Currency>(payee)) + amount;
        ensures payer_addr == payee
            ==> DiemAccount::balance<Currency>(payee)
            == old(DiemAccount::balance<Currency>(payee));

        aborts_with [check]
            Errors::NOT_PUBLISHED,
            Errors::INVALID_STATE,
            Errors::INVALID_ARGUMENT,
            Errors::LIMIT_EXCEEDED;

        include DiemAccount::PayFromEmits<Currency>{cap: cap};

        /// **Access Control:**
        /// Both the payer and the payee must hold the balances of the Currency. Only Designated Dealers,
        /// Parent VASPs, and Child VASPs can hold balances [[D1]][ROLE][[D2]][ROLE][[D3]][ROLE][[D4]][ROLE][[D5]][ROLE][[D6]][ROLE][[D7]][ROLE].
        aborts_if !exists<DiemAccount::Balance<Currency>>(payer_addr) with Errors::NOT_PUBLISHED;
        aborts_if !exists<DiemAccount::Balance<Currency>>(payee) with Errors::INVALID_ARGUMENT;
    }

}
