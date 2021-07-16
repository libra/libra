//! account: bob, 100000000
//! account: alice, 100000000

// ****
// Account setup - bob is account with nonce resource and alice is a regular account
// ****

// TODO: This is commented out because SlidingNonce::publish is a friend to DiemAccount
// so this script cannot access it.  It's preserved because it will soon become a unit test.
// //! new-transaction
// //! sender: bob
// script {
//     use DiemFramework::SlidingNonce;

//     fun main(account: signer) {
//     let account = &account;
//         SlidingNonce::publish(account);

//         // 0-nonce is always allowed
//         SlidingNonce::record_nonce_or_abort(account, 0);
//         SlidingNonce::record_nonce_or_abort(account, 0);

//         // Repeating nonce is not allowed
//         SlidingNonce::record_nonce_or_abort(account, 1);
//         assert(SlidingNonce::try_record_nonce(account, 1) == 3, 1);
//         SlidingNonce::record_nonce_or_abort(account, 2);

//         // Can execute 1000 + 127 once(but not second time) and then 1000, because distance between them is <128
//         SlidingNonce::record_nonce_or_abort(account, 1000 + 127);
//         assert(SlidingNonce::try_record_nonce(account, 1000 + 127) == 3, 1);
//         SlidingNonce::record_nonce_or_abort(account, 1000);

//         // Can execute 2000 + 128 but not 2000, because distance between them is <128
//         SlidingNonce::record_nonce_or_abort(account, 2000 + 128);
//         assert(SlidingNonce::try_record_nonce(account, 2000) == 1, 1);

//         // Big jump is nonce is not allowed
//         assert(SlidingNonce::try_record_nonce(account, 20000) == 2, 1);
//     }
// }
// // check: "Keep(EXECUTED)"

//! new-transaction
//! sender: alice
script {
    use DiemFramework::SlidingNonce;

    fun main(account: signer) {
    let account = &account;
        SlidingNonce::record_nonce_or_abort(account, 0);
        SlidingNonce::record_nonce_or_abort(account, 0);
    }
}
// check: "Keep(EXECUTED)"
