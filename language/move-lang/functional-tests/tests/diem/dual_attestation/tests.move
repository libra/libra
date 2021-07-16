//! account: freddymac
//! account: bob, 0, 0, address

//! new-transaction
//! sender: freddymac
script{
    use DiemFramework::DualAttestation;
    fun main() {
        DualAttestation::get_cur_microdiem_limit();
    }
}
// check: "Keep(EXECUTED)"

//! new-transaction
script{
    use DiemFramework::DualAttestation::{Self};
    fun main(not_blessed: signer) {
    let not_blessed = &not_blessed;
        DualAttestation::set_microdiem_limit(not_blessed, 99);
    }
}
// check: "Keep(ABORTED { code: 258,"

//! new-transaction
//! sender: blessed
script{
    use DiemFramework::DualAttestation::{Self};
    fun main(not_blessed: signer) {
    let not_blessed = &not_blessed;
        DualAttestation::set_microdiem_limit(not_blessed, 1001);
    }
}
// check: "Keep(EXECUTED)"

// TODO: DualAttestation::publish_credential is now a friend function
// Make this into a unit test.
// //! new-transaction
// //! sender: blessed
// script{
//     use DiemFramework::DualAttestation;
//     fun main(account: signer) {
//     let account = &account;
//         DualAttestation::publish_credential(account, account, x"");
//     }
// }
// // check: "Keep(ABORTED { code: 1283,"

// TODO: Make into unit test
// //! new-transaction
// //! sender: blessed
// script{
//     use DiemFramework::DualAttestation;
//     fun main(account: signer) {
//     let account = &account;
//         DualAttestation::publish_credential(account, account, x"");
//     }
// }
// // check: "Keep(ABORTED { code: 1283,"

//! new-transaction
//! sender: blessed
//! type-args: 0x1::XUS::XUS
//! args: 0, {{bob}}, {{bob::auth_key}}, b"bob", true
stdlib_script::AccountCreationScripts::create_parent_vasp_account
// check: "Keep(EXECUTED)"

// TODO: Make into unit test
// //! new-transaction
// //! sender: bob
// script{
//     use DiemFramework::DualAttestation;
//     fun main(account: signer) {
//     let account = &account;
//         DualAttestation::publish_credential(account, account, x"");
//     }
// }
// // check: "Keep(ABORTED { code: 258,"

//! new-transaction
//! sender: blessed
script{
    use DiemFramework::DualAttestation;
    fun main(account: signer) {
    let account = &account;
        DualAttestation::rotate_base_url(account, x"");
    }
}
// check: "Keep(ABORTED { code: 5,"

//! new-transaction
//! sender: bob
script{
    use DiemFramework::DualAttestation;
    fun main(account: signer) {
    let account = &account;
        DualAttestation::rotate_base_url(account, x"");
    }
}
// check: BaseUrlRotationEvent
// check: "Keep(EXECUTED)"


//! new-transaction
//! sender: blessed
script{
    use DiemFramework::DualAttestation;
    fun main(account: signer) {
    let account = &account;
        DualAttestation::rotate_compliance_public_key(account, x"");
    }
}
// check: "Keep(ABORTED { code: 5,"

//! new-transaction
//! sender: bob
script{
    use DiemFramework::DualAttestation;
    fun main(account: signer) {
    let account = &account;
        DualAttestation::rotate_compliance_public_key(account, x"");
    }
}
// check: "Keep(ABORTED { code: 519,"

//! new-transaction
//! sender: bob
script{
    use DiemFramework::DualAttestation;
    fun main(account: signer) {
    let account = &account;
        DualAttestation::initialize(account);
    }
}
// check: "Keep(ABORTED { code: 1,"

//! new-transaction
//! sender: bob
script{
    use DiemFramework::DualAttestation;
    fun main(account: signer) {
    let account = &account;
        DualAttestation::initialize(account);
    }
}
// check: "Keep(ABORTED { code: 1,"

// TODO: Make into unit test
// //! new-transaction
// //! sender: diemroot
// //! execute-as: freddymac
// script{
// use DiemFramework::DualAttestation;
// fun main(dr_account: signer, freddy: signer) {
//     let dr_account = &dr_account;
//     let freddy = &freddy;
//     DualAttestation::publish_credential(freddy, dr_account, b"freddy");
//     DualAttestation::publish_credential(freddy, dr_account, b"freddy");
// }
// }
// // check: "Discard(INVALID_WRITE_SET)"

//! new-transaction
script{
use DiemFramework::DualAttestation;
fun main() {
    DualAttestation::human_name(@{{freddymac}});
}
}
// check: "Keep(ABORTED { code: 5,"

//! new-transaction
script{
use DiemFramework::DualAttestation;
fun main() {
    DualAttestation::base_url(@{{freddymac}});
}
}
// check: "Keep(ABORTED { code: 5,"

//! new-transaction
script{
use DiemFramework::DualAttestation;
fun main() {
    DualAttestation::compliance_public_key(@{{freddymac}});
}
}
// check: "Keep(ABORTED { code: 5,"

//! new-transaction
script{
use DiemFramework::DualAttestation;
fun main() {
    DualAttestation::expiration_date(@{{freddymac}});
}
}
// check: "Keep(ABORTED { code: 5,"
