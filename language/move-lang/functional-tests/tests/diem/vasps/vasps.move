//! account: parent, 0, 0, address
//! account: bob, 10000000

// create a parent VASP
//! new-transaction
//! sender: blessed
script {
use DiemFramework::DualAttestation;
use DiemFramework::XUS::XUS;
use DiemFramework::DiemAccount;
use DiemFramework::DiemTimestamp;
use DiemFramework::VASP;
fun main(dr_account: signer) {
    let dr_account = &dr_account;
    let add_all_currencies = false;

    DiemAccount::create_parent_vasp_account<XUS>(
        dr_account,
        @{{parent}},
        {{parent::auth_key}},
        x"A1",
        add_all_currencies,
    );

    assert(VASP::is_vasp(@{{parent}}), 2001);
    assert(VASP::is_parent(@{{parent}}), 2002);
    assert(!VASP::is_child(@{{parent}}), 2003);

    assert(VASP::parent_address(@{{parent}}) == @{{parent}}, 2005);
    assert(DualAttestation::compliance_public_key(@{{parent}}) == x"", 2006);
    assert(DualAttestation::human_name(@{{parent}}) == x"A1", 2007);
    assert(DualAttestation::base_url(@{{parent}}) == x"", 2008);
    assert(
        DualAttestation::expiration_date(@{{parent}}) > DiemTimestamp::now_microseconds(),
        2009
    );

}
}
// check: CreateAccountEvent
// check: "Keep(EXECUTED)"

// create some child VASP accounts
//! new-transaction
//! sender: parent
script {
use DiemFramework::DiemAccount;
use DiemFramework::XUS::XUS;
use DiemFramework::VASP;
fun main(parent_vasp: signer) {
    let parent_vasp = &parent_vasp;
    let dummy_auth_key_prefix = x"00000000000000000000000000000000";
    let add_all_currencies = false;
    assert(VASP::num_children(@{{parent}}) == 0, 2010);
    DiemAccount::create_child_vasp_account<XUS>(
        parent_vasp, @0xAA, copy dummy_auth_key_prefix, add_all_currencies
    );
    assert(VASP::num_children(@{{parent}}) == 1, 2011);
    assert(VASP::parent_address(@0xAA) == @{{parent}}, 2012);
    DiemAccount::create_child_vasp_account<XUS>(
        parent_vasp, @0xBB, dummy_auth_key_prefix, add_all_currencies
    );
    assert(VASP::num_children(@{{parent}}) == 2, 2013);
    assert(VASP::parent_address(@0xBB) == @{{parent}}, 2014);
}
}
// check: CreateAccountEvent
// check: "Keep(EXECUTED)"

//! new-transaction
//! sender: parent
script {
use DiemFramework::DualAttestation;
fun main(parent_vasp: signer) {
    let parent_vasp = &parent_vasp;
    let old_pubkey = DualAttestation::compliance_public_key(@{{parent}});
    let new_pubkey = x"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    assert(old_pubkey != copy new_pubkey, 2011);
    DualAttestation::rotate_compliance_public_key(parent_vasp, copy new_pubkey);
    assert(DualAttestation::compliance_public_key(@{{parent}}) == new_pubkey, 2015);
}
}
// check: ComplianceKeyRotationEvent
// check: "Keep(EXECUTED)"

// getting the parent VASP address of a non-VASP should abort
//! new-transaction
//! sender: bob
script {
use DiemFramework::VASP;
fun main() {
    assert(VASP::parent_address(@{{bob}}) == @{{parent}}, 2016);
}
}
// check: "Keep(ABORTED { code: 519,"

// TODO: VASP::publish_parent_vasp_credential is now a friend function
// Make into unit test.
// //! new-transaction
// //! sender: blessed
// script {
// use DiemFramework::VASP;
// fun main(account: signer) {
//     let account = &account;
//     VASP::publish_parent_vasp_credential(account, account);
//     abort 99
// }
// }
// // check: "Keep(ABORTED { code: 771,"

// //! new-transaction
// //! sender: diemroot
// script {
// use DiemFramework::VASP;
// fun main(account: signer) {
//     let account = &account;
//     VASP::publish_parent_vasp_credential(account, account);
// }
// }
// // check: "Keep(ABORTED { code: 258,"

// //! new-transaction
// //! sender: blessed
// script {
// use DiemFramework::VASP;
// fun main(account: signer) {
//     let account = &account;
//     VASP::publish_child_vasp_credential(account, account);
// }
// }
// // check: "Keep(ABORTED { code: 771,"

// //! new-transaction
// //! sender: blessed
// script {
// use DiemFramework::VASP;
// fun main(account: signer) {
//     let account = &account;
//     VASP::publish_child_vasp_credential(account, account);
// }
// }
// // check: "Keep(ABORTED { code: 771,"

// //! new-transaction
// //! sender: parent
// script {
// use DiemFramework::VASP;
// fun main(account: signer) {
//     let account = &account;
//     VASP::publish_child_vasp_credential(account, account);
// }
// }
// // check: "Keep(ABORTED { code: 2307,"

//! new-transaction
//! sender: parent
script {
use DiemFramework::VASP;
fun main() {
    assert(!VASP::is_same_vasp(@{{parent}}, @{{blessed}}), 42);
}
}
// check: "Keep(EXECUTED)"

//! new-transaction
//! sender: parent
script {
use DiemFramework::VASP;
fun main() {
    assert(!VASP::is_same_vasp(@{{blessed}}, @{{parent}}), 42);
}
}
// check: "Keep(EXECUTED)"
