script {
use DiemFramework::DiemAccount;
use DiemFramework::SlidingNonce;

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
/// ## Events
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
/// | `tc_account`                | `&signer` | The signer reference of the sending account of this transaction. Must be the Treasury Compliance account.  |
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
/// * `Script::create_designated_dealer`
/// * `Script::peer_to_peer_with_metadata`
/// * `Script::rotate_dual_attestation_info`

fun tiered_mint<CoinType>(
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
}
