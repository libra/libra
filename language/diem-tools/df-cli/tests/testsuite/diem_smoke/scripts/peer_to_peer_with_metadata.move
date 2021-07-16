script {
use DiemFramework::DiemAccount;

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
/// `metadata` and an (optional) `metadata_signature` on the message
/// `metadata` | `Signer::address_of(payer)` | `amount` | `DualAttestation::DOMAIN_SEPARATOR`.
/// The `metadata` and `metadata_signature` parameters are only required if `amount` >=
/// `DualAttestation::get_cur_microdiem_limit` XDX and `payer` and `payee` are distinct VASPs.
/// However, a transaction sender can opt in to dual attestation even when it is not required
/// (e.g., a DesignatedDealer -> VASP payment) by providing a non-empty `metadata_signature`.
/// Standardized `metadata` BCS format can be found in `diem_types::transaction::metadata::Metadata`.
///
/// ## Events
/// Successful execution of this script emits two events:
/// * A `DiemAccount::SentPaymentEvent` on `payer`'s `DiemAccount::DiemAccount` `sent_events` handle; and
/// * A `DiemAccount::ReceivedPaymentEvent` on `payee`'s `DiemAccount::DiemAccount` `received_events` handle.
///
/// # Parameters
/// | Name                 | Type         | Description                                                                                                                  |
/// | ------               | ------       | -------------                                                                                                                |
/// | `Currency`           | Type         | The Move type for the `Currency` being sent in this transaction. `Currency` must be an already-registered currency on-chain. |
/// | `payer`              | `&signer`    | The signer reference of the sending account that coins are being transferred from.                                           |
/// | `payee`              | `address`    | The address of the account the coins are being transferred to.                                                               |
/// | `metadata`           | `vector<u8>` | Optional metadata about this payment.                                                                                        |
/// | `metadata_signature` | `vector<u8>` | Optional signature over `metadata` and payment information. See                                                              |
///
/// # Common Abort Conditions
/// | Error Category             | Error Reason                                     | Description                                                                                                                         |
/// | ----------------           | --------------                                   | -------------                                                                                                                       |
/// | `Errors::NOT_PUBLISHED`    | `DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY`      | `payer` doesn't hold a balance in `Currency`.                                                                                       |
/// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EINSUFFICIENT_BALANCE`            | `amount` is greater than `payer`'s balance in `Currency`.                                                                           |
/// | `Errors::INVALID_ARGUMENT` | `DiemAccount::ECOIN_DEPOSIT_IS_ZERO`            | `amount` is zero.                                                                                                                   |
/// | `Errors::NOT_PUBLISHED`    | `DiemAccount::EPAYEE_DOES_NOT_EXIST`            | No account exists at the `payee` address.                                                                                           |
/// | `Errors::INVALID_ARGUMENT` | `DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE` | An account exists at `payee`, but it does not accept payments in `Currency`.                                                        |
/// | `Errors::INVALID_STATE`    | `AccountFreezing::EACCOUNT_FROZEN`               | The `payee` account is frozen.                                                                                                      |
/// | `Errors::INVALID_ARGUMENT` | `DualAttestation::EMALFORMED_METADATA_SIGNATURE` | `metadata_signature` is not 64 bytes.                                                                                               |
/// | `Errors::INVALID_ARGUMENT` | `DualAttestation::EINVALID_METADATA_SIGNATURE`   | `metadata_signature` does not verify on the against the `payee'`s `DualAttestation::Credential` `compliance_public_key` public key. |
/// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EWITHDRAWAL_EXCEEDS_LIMITS`       | `payer` has exceeded its daily withdrawal limits for the backing coins of XDX.                                                      |
/// | `Errors::LIMIT_EXCEEDED`   | `DiemAccount::EDEPOSIT_EXCEEDS_LIMITS`          | `payee` has exceeded its daily deposit limits for XDX.                                                                              |
///
/// # Related Scripts
/// * `Script::create_child_vasp_account`
/// * `Script::create_parent_vasp_account`
/// * `Script::add_currency_to_account`

fun peer_to_peer_with_metadata<Currency>(
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
}
