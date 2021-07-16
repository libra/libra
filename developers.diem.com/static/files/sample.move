//! account: alice, 90000
//! account: bob, 90000

//! sender: alice
//! args: {{bob}}
use 0x0::Transaction;
use 0x0::DiemAccount;

fun main(receiver: address) {
    let balance_before = DiemAccount::balance(Transaction::sender());
    DiemAccount::deposit(receiver, DiemAccount::withdraw_from_sender(200));
    let balance_after = DiemAccount::balance(Transaction::sender());
    Transaction::assert(balance_before == balance_after + 200, 42);
}
// check: EXECUTED


//! new-transaction
//! sender: bob
use 0x0::Transaction;
use 0x0::DiemAccount;

fun main() {
    Transaction::assert(DiemAccount::balance(Transaction::sender()) == 90200, 42);
}
// check: EXECUTED


//! new-transaction
//! sender: bob
//! args: {{alice}}
use 0x0::DiemAccount;

fun main(receiver: address) {
    DiemAccount::deposit(receiver, DiemAccount::withdraw_from_sender(100000));
}
// check: ABORTED 10
