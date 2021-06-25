//! account: bob, 0,0, address
//! account: validatorvivian, 10000000XUS, 0, validator

// TODO: Commented out because DesignatedDealer::publish_designated_dealer_credential
// is now a friend, so not accessible.  Keeping the code because it will soon become
// a unit test.
// //! new-transaction
// script {
// use DiemFramework::DesignatedDealer;
// use DiemFramework::XUS::XUS;
// fun main(account: signer) {
//     let account = &account;
//     DesignatedDealer::publish_designated_dealer_credential<XUS>(
//         account, account, false
//     );
// }
// }
// // check: "Keep(ABORTED { code: 258,"

// TODO: friend function problem
// //! new-transaction
// //! sender: blessed
// script {
// use DiemFramework::DesignatedDealer;
// use DiemFramework::XUS::XUS;
// fun main(account: signer) {
//     let account = &account;
//     DesignatedDealer::publish_designated_dealer_credential<XUS>(
//         account, account, false
//     );
// }
// }
// // check: "Keep(ABORTED { code: 1539,"

//! new-transaction
script {
use DiemFramework::DesignatedDealer;
use DiemFramework::XUS::XUS;
fun main(account: signer) {
    let account = &account;
    DesignatedDealer::add_currency<XUS>(account, account);
}
}
// check: "Keep(ABORTED { code: 258,"

//! new-transaction
//! sender: blessed
script {
use DiemFramework::DesignatedDealer;
use DiemFramework::XUS::XUS;
fun main(account: signer) {
    let account = &account;
    DesignatedDealer::add_currency<XUS>(account, account);
}
}
// check: "Keep(ABORTED { code: 5,"

//! new-transaction
//! sender: blessed
//! type-args: 0x1::XUS::XUS
//! args: 0, {{bob}}, {{bob::auth_key}}, x"", false
stdlib_script::AccountCreationScripts::create_designated_dealer
// check: CreateAccountEvent
// check: "Keep(EXECUTED)"


//! new-transaction
//! sender: blessed
script {
use DiemFramework::DesignatedDealer;
use DiemFramework::XUS::XUS;
use DiemFramework::Diem;
fun main(account: signer) {
    let account = &account;
    Diem::destroy_zero(
        DesignatedDealer::tiered_mint<XUS>(account, 0, @{{bob}}, 0)
    );
}
}
// check: "Keep(ABORTED { code: 1031,"

//! new-transaction
//! sender: blessed
script {
    use DiemFramework::DiemAccount;
    use DiemFramework::XUS::XUS;
    use DiemFramework::Diem;
    fun main(tc_account: signer) {
    let tc_account = &tc_account;
        DiemAccount::tiered_mint<XUS>(
            tc_account, @{{bob}},  500000 * Diem::scaling_factor<XUS>() - 1, 0
        );
    }
}
// check: ReceivedMintEvent
// check: MintEvent
// check: "Keep(EXECUTED)"

//! block-prologue
//! proposer: validatorvivian
//! block-time: 95000000000

//! new-transaction
//! sender: blessed
//! expiration-time: 95000000001
script {
    use DiemFramework::DiemAccount;
    use DiemFramework::XUS::XUS;
    use DiemFramework::Diem;
    fun main(tc_account: signer) {
    let tc_account = &tc_account;
        DiemAccount::tiered_mint<XUS>(
            tc_account, @{{bob}},  500000 * Diem::scaling_factor<XUS>() - 1, 0
        );
    }
}
// check: ReceivedMintEvent
// check: MintEvent
// check: "Keep(EXECUTED)"
