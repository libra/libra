---
id: transaction-types
title: Transaction Types
sidebar_label: Transaction Types
---



There are different types of transactions that can be sent by different types of accounts:


* Transactions to create accounts and for minting and burning.
* Transactions to help with account administration.
* Transactions to send payments.


We will be linking to certain transaction scripts in this documentation, which will provide more detailed descriptions of each parameter.

## Account creation and minting

Creating an [account](accounts.md) for the Diem Payment Network (DPN) is different for testnet, mainnet, and pre-mainnet.

### Testnet
In [**testnet**](reference/glossary.md#testnet), there is a [faucet service](/reference/glossary.md#faucet) endpoint where you can send requests so that you can perform certain actions that can only be performed by the Diem Association on mainnet. The faucet service endpoint can be used to create ParentVASP accounts and to give you fake Diem Coins for testing.

To create a ParentVASP account in testnet, send a request like the code example below to the faucet server:


`http://<faucet server address>/?amount=<amount>&auth_key=<auth_key>&currency_code=<currency_code>`

* `auth_key`: The authorization key for an account.
* `amount`: The amount of money available as the account balance.
* `currency_code`: The specified currency for the amount.

This request first checks if there is an account available for the authorization key. If the account given by `auth_key` doesn’t exist, a ParentVASP account will be created with the balance of the amount in the currency_code  specified. If the account already exists, this will simply give the `account` the specified amount of `currency_code` Diem Coins.


### Mainnet and pre-mainnet

In **mainnet** and **pre-mainnet**, account creation and minting are different.

If you are a Regulated VASP, and have been approved by Diem Networks as a participant on DPN, you first need to complete an application with Diem Networks to have a ParentVASP account created on your behalf. Once Diem Networks creates your ParentVASP account (let’s call it Account A), you can create a ChildVASP account if you wish.


To create a ChildVASP account, you must send the [create_child_vasp_account](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#script-create_child_vasp_account-1) transaction script from your **Account A** (your ParentVASP account). You can create upto 256 ChildVASP accounts with your single ParentVASP one. In this transaction script, you can specify which currency the new account should hold, or if it should hold all known currencies. Additionally, you can initialize the ChildVASP account with a specified amount of coins in a given currency.

A Regulated VASP can purchase Diem Coins from a Designated Dealer.



## Account administration
Once an account has been created, there are a number of operations that can be performed to rotate an account’s authentication key, add currencies to an account, or add a recovery address that can be used in case an account loses its private key.

### Account recovery
If a Regulated VASP V wishes to designate one of its accounts R as a recovery address account, it can do so by sending a [create_recovery_address](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#script-create_recovery_address) transaction from R. The recovery address account should be a cold account (i.e., no transactions should be planned to be sent from that account).

This account should only be used for rotating the authentication key of an account that has registered itself with R and whose private key has been lost. After the recovery address R has been created, other accounts that belong to the VASP V can register themselves with R by sending an [add_recovery_rotation_capability](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#script-add_recovery_rotation_capability-1) transaction and specifying the recovery address as R.

### Authentication key rotation
If an account A wishes to update the authentication key needed to access it, it can do so by sending one of two transactions, depending on whether A has been registered with (or is) an account recovery address.


If A has not registered itself with a recovery address, it can change its authentication key by sending a [rotate_authentication_key](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#script-rotate_authentication_key-1) transaction with its new auth key. If A is part of a recovery address, then it can rotate its key by sending a [rotate_authentication_key_with_recovery_address](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#rotate_authentication_key_with_recovery_address) transaction with its new authentication key, and itself as the `to_recover` address.

### Adding a currency to an account
If an account A wishes to hold a balance of Diem Coins in a currency C that it currently doesn’t hold, it can add a balance for C to A by sending an [add_currency_to_account](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#add_currency_to_account) transaction from A, and specifying C as the currency. It’s important to note that C must be a recognized currency on-chain, and A cannot hold a balance in C already; otherwise, this transaction will fail to execute.

## Payments
If an account **A** wishes to send a payment to another account **B,** it can do so by sending a [peer_to_peer_with_metadata](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#peer_to_peer_with_metadata) script transaction. When a payment is made, the sender must specify the currency the payment is being made in, the amount to send, and the account the payment is being made to (e.g., B). Account A can also specify when constructing a transaction: the metadata parameter which can be of any form as long as A and B agree on it subject to certain rules specified in the Regulated VASP’s agreement with Diem Networks, and a  `metadata_signature` used for dual attestation, as is discussed in the next section.

### Dual attestation
Every payment transaction between two distinct Regulated VASP accounts that sends an amount that exceeds a certain threshold, which is currently $1,000, must perform dual attestation in order to comply with the Travel Rule. "Dual attestation" means the sending VASP  must send the Receiving VASP  certain data to the endpoint given by the recipient’s  `base_url`, after which the receiving VASP can perform checks on this data. The receiving VASP then signs this data with the compliance private key that corresponds to their `compliance_public_key` held on-chain, and sends it back to the sending VASP.. The sending VASP must then include this signed data in the payment transaction and the signature will be checked on-chain.

### Updating dual attestation information
If a Regulated VASP wishes to update its base_url and/or its `compliance_public_key` (for example, if it wishes to change the private key it uses to sign metadata for dual attestation), it can do so by sending a [rotate_dual_attestation_info](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#script-rotate_dual_attestation_info-1) transaction from the ParentVASP account (the account that holds the DualAttestation information). After this transaction has been executed, all transactions that are subject to dual attestation will be checked using the new compliance_public_key of the receiving account. Because of this, Regulated VASPs should be careful to communicate this change and ensure that there are no outstanding payment transactions that they have previously signed but that have not yet been committed on-chain, since these will be rejected if the `compliance_public_key` has changed.



###### tags: `core`
