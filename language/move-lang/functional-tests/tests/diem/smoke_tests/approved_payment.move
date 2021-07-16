// Module that allows a payee to approve payments with a cryptographic signature. The basic flow is:
// (1) Payer sends `metadata` to the payee
// (2) Payee signs `metadata` and sends 64 byte signature back to the payer
// (3) Payer sends an approved payment to the payee by sending a transaction invoking `deposit`
//     with payment metadata + signature. The transaction will abort if the signature check fails.
// Note: approved payments are an accounting convenience/a courtesy mechansim for the payee, *not*
// a hurdle that must be cleared for all payments to the payee. In addition, approved payments do
// not have replay protection.
module {{default}}::ApprovedPayment {
    use DiemFramework::Diem::{Self, Diem};
    use DiemFramework::Signature;
    use Std::Signer;
    use Std::Vector;

    // A resource to be published under the payee's account
    struct T has key {
        // 32 byte single Ed25519 public key whose counterpart must be used to sign the payment
        // metadata. Note that this is different (and simpler) than the `authentication_key` used in
        // DiemAccount, which is a hash of a public key + signature scheme identifier.
        public_key: vector<u8>,
        // TODO: events?
    }

    // Deposit `coin` in `payee`'s account if the `signature` on the payment metadata matches the
    // public key stored in the `approved_payment` resource
    public fun deposit<Token>(
        _payer: &signer,
        approved_payment: &T,
        _payee: address,
        coin: Diem<Token>,
        metadata: vector<u8>,
        signature: vector<u8>
    ) {
        // Sanity check of signature validity
        assert(Vector::length(&signature) == 64, 9001); // TODO: proper error code
        // Cryptographic check of signature validity
        assert(
            Signature::ed25519_verify(
                signature,
                *&approved_payment.public_key,
                copy metadata
            ),
            9002, // TODO: proper error code
        );
        //DiemAccount::deposit_with_metadata<Token>(payer, payee, coin, metadata, x"")
        // TODO: DiemAccount APIs no longer support depositing a coin stored in a local
        Diem::destroy_zero(coin);
    }

    // Wrapper of `deposit` that withdraw's from the sender's balance and uses the top-level
    // `ApprovedPayment` resource under the payee account.
    public fun deposit_to_payee<Token>(
        payer: &signer,
        payee: address,
        _amount: u64,
        metadata: vector<u8>,
        signature: vector<u8>
    ) acquires T {
        deposit<Token>(
            payer,
            borrow_global<T>(payee),
            payee,
            // TODO: DiemAccount APIs no longer support withdrawing a coin into a local
            //DiemAccount::withdraw_from<Token>(&with_cap, amount),
            Diem::zero<Token>(),
            metadata,
            signature
        );
    }

    // Rotate the key used to sign approved payments. This will invalidate any approved payments
    // that are currently in flight
    public fun rotate_key(approved_payment: &mut T, new_public_key: vector<u8>) {
        // Cryptographic check of public key validity
        assert(
            Signature::ed25519_validate_pubkey(
                copy new_public_key
            ),
            9003, // TODO: proper error code
        );
        approved_payment.public_key = new_public_key
    }

    // Wrapper of `rotate_key` that rotates the sender's key
    public fun rotate_sender_key(sender: &signer, new_public_key: vector<u8>) acquires T {
        // Sanity check for key validity
        assert(Vector::length(&new_public_key) == 32, 9003); // TODO: proper error code
        rotate_key(borrow_global_mut<T>(Signer::address_of(sender)), new_public_key)
    }

    // Publish an ApprovedPayment resource under the sender's account with approval key
    // `public_key`
    public fun publish(account: &signer, public_key: vector<u8>) {
        // Sanity check for key validity
        assert(
            Signature::ed25519_validate_pubkey(
                copy public_key
            ),
            9003, // TODO: proper error code
        );
        move_to(account, T { public_key })
    }

    // Remove and destroy the ApprovedPayment resource under the sender's account
    public fun unpublish_from_sender(sender: &signer) acquires T {
        let T { public_key: _ } = move_from<T>(Signer::address_of(sender));
    }

    // Return true if an ApprovedPayment resource exists under `addr`
    public fun exists_at(addr: address): bool {
        exists<T>(addr)
    }

}

// === Key lengths tests ===

// Test that publishing a key with an invalid length or rotating to a key with an invalid length
// causes failures.

//! account: alice

//! new-transaction
//! sender: alice
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let invalid_pubkey = x"aa"; // too short
    ApprovedPayment::publish(account, invalid_pubkey)
}
}
// check: "Keep(ABORTED { code: 9003,"

// publish with a valid pubkey...

//! new-transaction
//! sender: alice
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let pubkey = x"7013b6ed7dde3cfb1251db1b04ae9cd7853470284085693590a75def645a926d";
    ApprovedPayment::publish(account, pubkey)
}
}

// check: "Keep(EXECUTED)"

// ... but then rotate to an invalid one

//! new-transaction
//! sender: alice
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let invalid_pubkey = x"aa"; // too short
    ApprovedPayment::rotate_sender_key(account, invalid_pubkey)
}
}
// check: "Keep(ABORTED { code: 9003,"


// === publish/unpublish tests ===

//! account: alice1

//! new-transaction
//! sender: alice1
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    assert(!ApprovedPayment::exists_at(@{{alice1}}), 6001);
    let pubkey = x"aa306695ca5ade60240c67b9b886fe240a6f009b03e43e45838334eddeae49fe";
    ApprovedPayment::publish(account, pubkey);
    assert(ApprovedPayment::exists_at(@{{alice1}}), 6002);
    ApprovedPayment::unpublish_from_sender(account);
    assert(!ApprovedPayment::exists_at(@{{alice1}}), 6003);
}
}
// check: "Keep(EXECUTED)"

// === rotate key tests ===
// Test that rotating the key used to pre-approve payments works

//! account: alice2
//! account: bob2
//! account: charlie2

// setup: alice publishes an approved payment resource, then rotates the key

//! new-transaction
//! sender: alice2
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let pubkey = x"aa306695ca5ade60240c67b9b886fe240a6f009b03e43e45838334eddeae49fe";
    ApprovedPayment::publish(account, pubkey);
    ApprovedPayment::rotate_sender_key(account, x"7013b6ed7dde3cfb1251db1b04ae9cd7853470284085693590a75def645a926d");
}
}
// check: "Keep(EXECUTED)"

// offline: alice2 generates payment id 0, signs it, and sends ID + signature to bob2
// online: now bob2 puts the payment id and signature in transaction and uses it to pay alice2

//! new-transaction
//! sender: bob2
script {
use {{default}}::ApprovedPayment;
use DiemFramework::XDX::XDX;
fun main(account: signer) {
    let account = &account;
    let payment_id = x"0000000000000000000000000000000000000000000000000000000000000000";
    let signature = x"62d6be393b8ec77fb2c12ff44ca8b5bd8bba83b805171bc99f0af3bdc619b20b8bd529452fe62dac022c80752af2af02fb610c20f01fb67a4d72789db2b8b703";
    ApprovedPayment::deposit_to_payee<XDX>(account, @{{alice2}}, 1000, payment_id, signature);
}
}
// check: "Keep(EXECUTED)"

// charlie publishes an approved payment resource, then tries to rotate to an invalid key

//! new-transaction
//! sender: charlie2
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let pubkey = x"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    ApprovedPayment::publish(account, pubkey);
    // rotate to an invalid key
    ApprovedPayment::rotate_sender_key(account, x"0000000000000000000000000000000000000000000000000000000000000000");
}
}
// check: "Keep(ABORTED { code: 9003,"


// === signature checking tests ===

// Test the end-to-end approved payment flow by (1) pre-approving a payment to alice from bob with
// a valid signature from alice (should work) and (2) the same, but with an invalid signature
// (shouldn't work).

//! account: alice3
//! account: bob3
//! account: charlie3

// setup: alice publishes an approved payment resource

//! new-transaction
//! sender: alice3
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let pubkey = x"7013b6ed7dde3cfb1251db1b04ae9cd7853470284085693590a75def645a926d";
    ApprovedPayment::publish(account, pubkey)
}
}
// check: "Keep(EXECUTED)"

// offline: alice generates payment id 0, signs it, and sends ID + signature to bob
// online: now bob puts the payment id and signature in transaction and uses it to pay Alice

//! new-transaction
//! sender: bob3
script {
use {{default}}::ApprovedPayment;
use DiemFramework::XDX::XDX;
fun main(account: signer) {
    let account = &account;
    let payment_id = x"0000000000000000000000000000000000000000000000000000000000000000";
    let signature = x"62d6be393b8ec77fb2c12ff44ca8b5bd8bba83b805171bc99f0af3bdc619b20b8bd529452fe62dac022c80752af2af02fb610c20f01fb67a4d72789db2b8b703";
    ApprovedPayment::deposit_to_payee<XDX>(account, @{{alice3}}, 1000, payment_id, signature);
}
}
// check: "Keep(EXECUTED)"

// same as above, but with an invalid-length signature. should now abort

//! new-transaction
//! sender: bob3
script {
use {{default}}::ApprovedPayment;
use DiemFramework::XDX::XDX;
fun main(account: signer) {
    let account = &account;
    let payment_id = x"0000000000000000000000000000000000000000000000000000000000000000";
    let signature = x"";
    ApprovedPayment::deposit_to_payee<XDX>(account, @{{alice}}, 1000, payment_id, signature);
}
}

// check: "Keep(ABORTED { code: 9001,"

// same as above, but with an invalid signature. should now abort

//! new-transaction
//! sender: bob3
script {
use {{default}}::ApprovedPayment;
use DiemFramework::XDX::XDX;
fun main(account: signer) {
    let account = &account;
    let payment_id = x"07";
    let signature = x"62d6be393b8ec77fb2c12ff44ca8b5bd8bba83b805171bc99f0af3bdc619b20b8bd529452fe62dac022c80752af2af02fb610c20f01fb67a4d72789db2b8b703";
    ApprovedPayment::deposit_to_payee<XDX>(account, @{{alice3}}, 1000, payment_id, signature);
}
}
// check: "Keep(ABORTED { code: 9002,"

// charlie publishes an invalid approved payment resource (key too long)
//! new-transaction
//! sender: charlie3
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let pubkey = x"010000000000000000000000000000000000000000000000000000000000000000";
    ApprovedPayment::publish(account, pubkey);
}
}
// check: "Keep(ABORTED { code: 9003,"


// charlie publishes an invalid approved payment resource (key too short)
//! new-transaction
//! sender: charlie3
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let pubkey = x"0100";
    ApprovedPayment::publish(account, pubkey);
}
}
// check: "Keep(ABORTED { code: 9003,"

// charlie publishes an invalid approved payment resource (correct length,
// invalid key),
//! new-transaction
//! sender: charlie3
script {
use {{default}}::ApprovedPayment;
fun main(account: signer) {
    let account = &account;
    let pubkey = x"0000000000000000000000000000000000000000000000000000000000000000";
    ApprovedPayment::publish(account, pubkey);
}
}
// check: "Keep(ABORTED { code: 9003,"
