script {
use DiemFramework::DiemAccount;
use DiemFramework::SlidingNonce;

/// # Summary
/// Creates a Designated Dealer account with the provided information, and initializes it with
/// default mint tiers. The transaction can only be sent by the Treasury Compliance account.
///
/// # Technical Description
/// Creates an account with the Designated Dealer role at `addr` with authentication key
/// `auth_key_prefix` | `addr` and a 0 balance of type `Currency`. If `add_all_currencies` is true,
/// 0 balances for all available currencies in the system will also be added. This can only be
/// invoked by an account with the TreasuryCompliance role.
///
/// At the time of creation the account is also initialized with default mint tiers of (500_000,
/// 5000_000, 50_000_000, 500_000_000), and preburn areas for each currency that is added to the
/// account.
///
/// # Parameters
/// | Name                 | Type         | Description                                                                                                                                         |
/// | ------               | ------       | -------------                                                                                                                                       |
/// | `Currency`           | Type         | The Move type for the `Currency` that the Designated Dealer should be initialized with. `Currency` must be an already-registered currency on-chain. |
/// | `tc_account`         | `&signer`    | The signer reference of the sending account of this transaction. Must be the Treasury Compliance account.                                           |
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
/// * `Script::tiered_mint`
/// * `Script::peer_to_peer_with_metadata`
/// * `Script::rotate_dual_attestation_info`

fun create_designated_dealer<Currency>(
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
}
