//! account: bob, 10000XUS

//! new-transaction
//! sender: bob
//! max-gas: 700
//! gas-price: 1
//! gas-currency: XUS
script {
    fun main() { while (true) {} }
}
// check: "EXECUTION_FAILURE { status_code: OUT_OF_GAS,"
// check: "gas_used: 700,"
// check: "Keep(OUT_OF_GAS)"

//! new-transaction
//! sender: blessed
//! type-args: 0x1::XUS::XUS
script {
use DiemFramework::TransactionFee;
fun burn_txn_fees<CoinType>(blessed_account: signer) {
    TransactionFee::burn_fees<CoinType>(&blessed_account);
}
}
// check: PreburnEvent
// check: BurnEvent
// check: "Keep(EXECUTED)"

// No txn fee balance left to burn

//! new-transaction
//! sender: blessed
//! type-args: 0x1::XUS::XUS
script {
use DiemFramework::TransactionFee;
fun burn_txn_fees<CoinType>(blessed_account: signer) {
    TransactionFee::burn_fees<CoinType>(&blessed_account);
}
}

// check: "Keep(ABORTED { code: 1799,"
