//! account: bob, 1000000, 0, validator
//! account: vivian, 1000000, 0, validator
//! account: alice, 0, 0, address
//! account: alex, 0, 0, address

//! new-transaction
script {
use DiemFramework::DiemSystem;
fun main(account: signer) {
    let account = &account;
    DiemSystem::initialize_validator_set(account);
}
}
// check: "Keep(ABORTED { code: 1,"

//! new-transaction
script {
use DiemFramework::DiemSystem;
fun main() {
    let len = DiemSystem::validator_set_size();
    DiemSystem::get_ith_validator_address(len);
}
}
// check: "Keep(ABORTED { code: 1287,"

//! new-transaction
script {
    use DiemFramework::DiemSystem;
    fun main(account: signer) {
        let account = &account;
        DiemSystem::update_config_and_reconfigure(account, @{{bob}});
    }
}
// check: "Keep(ABORTED { code: 2051,"

//! new-transaction
//! sender: diemroot
//! args: 0, {{alice}}, {{alice::auth_key}}, b"alice"
stdlib_script::AccountCreationScripts::create_validator_operator_account
// check: CreateAccountEvent
// check: "Keep(EXECUTED)"

//! new-transaction
//! sender: bob
script {
    use DiemFramework::ValidatorConfig;
    fun main(account: signer) {
        let account = &account;
        ValidatorConfig::set_operator(account, @0x0);
    }
}
// check: "Keep(ABORTED { code: 775,"

//! new-transaction
//! sender: alice
script {
    use Std::Signer;
    use DiemFramework::ValidatorConfig;
    fun main(account: signer) {
        let account = &account;
        ValidatorConfig::set_operator(account, Signer::address_of(account))
    }
}
// check: "Keep(ABORTED { code: 1795,"

//! new-transaction
//! sender: alice
script {
    use DiemFramework::ValidatorConfig;
    fun main(account: signer) {
        let account = &account;
        ValidatorConfig::remove_operator(account)
    }
}
// check: "Keep(ABORTED { code: 1795,"

//! new-transaction
//! sender: alice
script {
    use DiemFramework::ValidatorConfig;
    fun main() {
        ValidatorConfig::get_human_name(@{{alice}});
    }
}
// check: "Keep(ABORTED { code: 5,"

//! new-transaction
//! sender: bob
script {
    use Std::Signer;
    use DiemFramework::ValidatorConfig;
    fun main(account: signer) {
        let account = &account;
        ValidatorConfig::set_operator(account, Signer::address_of(account))
    }
}
// check: "Keep(ABORTED { code: 775,"

//! new-transaction
//! sender: bob
script {
    use DiemFramework::ValidatorConfig;
    // delegate to alice
    fun main(account: signer) {
        let account = &account;
        ValidatorConfig::set_operator(account, @{{alice}});
        ValidatorConfig::remove_operator(account);
    }
}
// check: "Keep(EXECUTED)"

//! new-transaction
//! sender: bob
script {
    use DiemFramework::ValidatorConfig;
    fun main(account: signer) {
        let account = &account;
        ValidatorConfig::set_config(account, @{{vivian}}, x"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", x"", x"");
    }
}
// check: "Keep(ABORTED { code: 263,"

//! new-transaction
//! sender: bob
script {
    use DiemFramework::ValidatorConfig;
    fun main(account: signer) {
        let account = &account;
        ValidatorConfig::set_config(account, @{{vivian}}, x"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", x"", x"");
    }
}
// check: "Keep(ABORTED { code: 263,"

// TODO: ValidatorConfig::publish is now a friend function
// Make this into a unit test.
// //! new-transaction
// script {
//     use DiemFramework::ValidatorConfig;
//     fun main(account: signer) {
//         let account = &account;
//         ValidatorConfig::publish(account, account, x"")
//     }
// }
// // check: "Keep(ABORTED { code: 2,"

//! new-transaction
//! sender: bob
script {
    use DiemFramework::ValidatorConfig;
    fun main(account: signer) {
        let account = &account;
        ValidatorConfig::set_config(account, @{{bob}}, x"0000000000000000000000000000000000000000000000000000000000000000", x"", x"");
    }
}
// check: "Keep(ABORTED { code: 7"

//! new-transaction
//! sender: bob
script {
    use DiemFramework::ValidatorConfig;
    fun main() {
        let _ = ValidatorConfig::get_config(@{{alice}});
    }
}
// check: "Keep(ABORTED { code: 5,"

//! new-transaction
//! sender: bob
script {
    use DiemFramework::ValidatorConfig;
    fun main() {
        let config = ValidatorConfig::get_config(@{{bob}});
        let _ = ValidatorConfig::get_validator_network_addresses(&config);
    }
}
// check: "Keep(EXECUTED)"

//! new-transaction
//! sender: diemroot
//! args: 0, {{alex}}, {{alex::auth_key}}, b"alex"
stdlib_script::AccountCreationScripts::create_validator_operator_account
// check: "Keep(EXECUTED)"

// TODO: Make into unit test
// //! new-transaction
// //! sender: diemroot
// //! execute-as: alex
// script {
// use DiemFramework::ValidatorOperatorConfig;
// fun main(dr_account: signer, alex_signer: signer) {
//     let dr_account = &dr_account;
//     let alex_signer = &alex_signer;
//     ValidatorOperatorConfig::publish(alex_signer, dr_account, b"alex");
// }
// }
// // check: "Discard(INVALID_WRITE_SET)"
