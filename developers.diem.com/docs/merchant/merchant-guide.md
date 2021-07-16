---
id: merchant-guide
title: Integrate Your Merchant Store with DPN
---



## Overview

>
> **Note:** This guide is intended to provide a merchant-serving [Regulated Virtual Asset Service Provider (VASP)](reference/glossary.md#Regulated-VASP), with the necessary information needed to integrate a merchant store with the Diem Payment Network (DPN).  This guide assumes that you are a Regulated VASP, and that you have been permissioned by Diem Networks as a participant on DPN. This guide also assumes you have undergone and passed a Diem Networks security penetration test (PEN) to check for exploitable vulnerabilities.
>


## Getting Started

To start the integration process for DPN mainnet, you will need to [create your on-chain Regulated VASP account](#create-your-vasp-account). To create an account on testnet (Diem’s test network), you can follow the instructions [available here](core/my-first-transaction.md).



Before you create your Regulated VASP account, you will need to become familiar with some account concepts.

DPN supports the following on-chain institutional accounts:

* Regulated VASP Accounts: These accounts are reserved for [Regulated VASP](/reference/glossary.md#Regulated-VASP) that operate on the DPN usually on behalf of end users. These are of two types - [ParentVASP and ChildVASP accounts](#account-roles).
* Designated Dealer Accounts: These accounts are reserved for designated dealers that have contracted with Diem Networks to mint and burn Diem Coins.


#### Account roles

There are two kinds of Regulated VASP accounts: ParentVASP and ChildVASP.

The **ParentVASP account** is your unique root account. You can have only one parent account per company.

Diem Networks will create a ParentVASP account on your behalf with your authentication key. This parent account contains three key pieces of data:

* its `human_name: `Your unique account name.
* `base_url:` a URL containing an endpoint to hit for off-chain APIs like exchanging information to comply with the Travel Rule. This will contain a dummy value when the ParentVASP account is created.
* `compliance_public_key:` An ed5519 public key for authenticating signatures on Travel Rule payloads. This will contain a dummy value when the account is created.

>Note: Note: We recommend updating the dummy values for the base_url and compliance_public_key before sending any transactions. Though these can also be updated later before sending an off-chain transaction.

The **ChildVASP account** is the child of your ParentVASP account. You can have any number of ChildVASP accounts. They can help in maintaining a structured on-chain presence (e.g., separate cold/warm/hot accounts). You do not need to have ChildVASP accounts. A ChildVASP account stores the address of its ParentVASP.

Learn more about account concepts [here](core/accounts.md).

### Create Your VASP Account
![Figure 1.0 Steps to create your VASP account](https://lh3.googleusercontent.com/zugl1j3iyLgTL6U9hVQ8b1VAF5X3_zNiEezOzsgYj2sJ4-C_kPoiM9SM8BJtydfweZV1W1AuA6KlZx6R6qFqQPvyN4WCc1DBFqxOct9CXnsiL4lHQyQJBj8ZslJazNgMRKOkMZNo)

1. **[Generate Keys](core/accounts.md#addresses-authentication-keys-and-cryptographic-keys)**: Generate an ed25519 keypair and associated authentication key for your on-chain Regulated VASP account.
2. **Share Account Info**: Share the following with the Diem Networks Treasury offline.
    1. Your public key
    2. Initial currency: XUS, or ALL. Learn more about choosing currencies [here](#choose-currencies).
    3. A human-readable VASP name to use on-chain. Diem Networks will need to check if this is a unique value.
3. **DPN Creates Parent Account**: Diem Networks will send a transaction that creates a [ParentVASP account](#account-roles) with your authentication key.
4. **Set up Base URL and Compliance Public Key for Off-Chain APIs**: In order to use off-chain APIs, you must send a transaction to set the base URL and compliance public key values on your parent account using [this](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#script-rotate_dual_attestation_info) transaction script.
5. **Create Child Account**: If you want to, you can create a new [ChildVASP account](#account-roles) from your ParentVASP account using this transaction [script](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#script-create_child_vasp_account). You can only create ChildVASP accounts using your ParentVASP account.
6. **Start Transacting**: Once the previous steps have been completed, you can send transactions from your account on-chain using the keypair from step (1).


#### Choose Currencies
When you are creating your ParentVASP account, you will need to choose at least one Diem Coin currency. The Diem Coin currencies that are currently available on the DPN are:

*   `XUS`(a USD stablecoin)

At such time that more one Diem Coin currency is available, you can share with DPN which [Diem Coin currencies](core/accounts.md#currencies-and-balances]) you would like to associate with your account. You can also request DPN to choose all Diem Coin currencies available.

>
>Note: When available, at the Move level, these will be different generic instantiations of the same Diem type (i.e. `Diem<XUS>`).
>

You can [add new Diem Coin currencies to an existing account](core/transaction-types.md#adding-a-currency-to-an-account) via the `add_currency_to_account` transaction [script](https://github.com/diem/diem/blob/main/language/diem-framework/transaction_scripts/doc/transaction_script_documentation.md#script-add_currency_to_account). You can add all currencies offered on DPN to your child VASP accounts by using the `add_all_currencies` flag in the account creation scripts.


## Submit a Transaction on the Network
Once you have your own Regulated VASP account, you can start interacting with DPN. Before you submit your first transaction, you will need to:

* [**Learn How to Interact with DPN**](#how-to-interact-with-the-dpn): Learn how you can interact with the DPN using private full nodes.
* [**Set-up Off-chain APIs**](#how-and-when-to-use-off-chain-apis): Off-chain APIs to exchange data, where applicable..
* [**Choose Gas Values**](#choose-gas-values): The gas values that determine the computational resources used and the fees you will incur for each transaction.


#### Lifecycle of a Transaction

When you submit a transaction to the DPN, you are cryptographically signing a transaction script and then waiting (by listening to the event stream) for consensus from validators. The diagram below shows the flow of a transaction once it’s been submitted. Learn more about this flow [here](core/life-of-a-transaction.md).

![Figure 1.1 Lifecycle of a transaction](https://lh3.googleusercontent.com/Vp5Ko8_mIV5AIV6fPUZX361fCqqs1XJ44_q9Jhf6OaftznmyRplZAmczmnqjc8511ULBFKMQzzn_ZIliDK22oCQYN4gjO91JhByyHuZrQMpPUtXq1oCrSTXFDd0KwDYM3PFi6pSJ)

#### How to Interact with the DPN
The first step to submitting transactions to the DPN is determining how to connect and interact with it. The guidance for this differs slightly based on if you are a validator node operator or not.


##### For any DPN Participant
If you are not a validator node operator, you can do one of the following:

* Communicate with a validator operator or owner of a validator node to obtain dedicated access to the validator network, using either a full node or JSON-RPC as described above.
* Leverage the public full node network, again, deploying your own full node with a JSON-RPC endpoint.
* Access a public JSON-RPC endpoint.

On JSON-RPC:

* It is most likely that Regulated VASPs will leverage JSON-RPC to connect to the Diem Blockchain.
* The development time of your merchant store integration with the Diem Blockchain may be faster when done using JSON-RPC.

Additionally, you may also use your own private full node. It may:

* Provide faster access to blockchain state
* Give you the ability to leverage pub/sub solutions
* Allow you to more closely monitor your submitted transaction
* Provide additional redundancy -- when your private full node is unavailable you can easily fall back to the well-maintained public network



##### How to Use Off-Chain APIs

Off-Chain protocols are APIs and payload specifications to support compliance and scalability on the DPN. It is executed between pairs of Regulated VASPs, such as wallets, exchanges, or designated dealers, and allows Regulated VASPs to privately exchange payment information before, while, or after settling it on the Diem Blockchain.

These off-chain APIs also provide a means to  to comply with the Travel Rule and negotiate one-time identifiers for on-chain transactions, reducing transaction linkability. To establish a connection, VASPs will look up their counterparty’s on-chain account containing a base URL for their off-chain service.  Note that each entity using an Off-Chain API must make its own determination as to whether it satisfies Travel Rule compliance.

To use an off-chain API you will need to set  values for the base_url and compliance_public_key associated with your on-chain ParentVASP account.

You can read more about off-chain protocols [here](https://dip.diem.com/dip-1/).


### Choose Gas Values
In the Diem Payment Network, **gas** is used to track and measure the network resources used while executing a transaction.

##### Introduction to Gas
Gas is a way for the Move virtual machine to track and account for the abstract representation of computational resources consumed during execution. In other words, gas is used to track and measure the network resources used during a transaction in the Diem Payment Network (DPN).

Gas is used to ensure that all Move programs running on the Diem Blockchain terminate, so that the computational resources used are bounded. It also provides the ability to charge a transaction fee, partly based on consumed resources during a transaction.


##### Using gas to specify a transaction fee
When an account submits a transaction for execution to the Diem Blockchain, it contains a specified:

* `max_gas_amount`: This is the maximum amount of gas units that can be used to execute a transaction, and therefore bounds the amount of computational resources that can be consumed by a transaction.
* `gas_price`: This is a way to move from the abstract units of resource consumption that are used in the virtual machine (VM) — gas units — into a transaction fee in the specified gas currency.
* `gas_currency`: This is the currency of the transaction fee (which is at most `gas_price * max_gas_amount`) charged to the client.

> **Note**: At launch, we anticipate these charges will be zero. But during high congestion, you can specify a gas fee.


##### Choose Values

When an account submits a transaction for execution, **gas** is used to:

*   Track and account the computational resources used.
*   Limit the number of resources used during execution.
*   Charge a transaction fee based on the amount of resources used for execution.

You can do these by setting the following parameters:


When you submit a transaction for execution, you will use **gas** to:
* Track and account the computational resources used.
* Limit the number of resources used during execution.
* Charge a transaction fee based on the amount of resources used for execution.

You can do these by setting the following parameters:

| Definition | Set Value |
| -------------- | -------------- |
| `max_gas_units`: This is the maximum amount of gas units that can be used to execute a transaction. By setting a value for this parameter, you can ensure that a transaction uses only a certain number of computational resources. | To help you choose a value for `max_gas_amount`, we will be publishing a list of suggested `max_gas_amount` for each transaction before launch. We will be keeping the current lockdown restrictions the world-over in consideration for this list.<br/><br/>On testnet: `600 < max_gas_amount ≤ 2,000,000` |
| `gas_price`: This is a way to move from the abstract units of resource consumption that are used in the virtual machine (VM) — gas units — into a transaction fee in the specified gas currency. | For launch, you can set the `gas_price` to be zero or almost zero, allowing you to submit transactions without high charges. This is because the network shouldn’t have high contention.<br/><br/>On testnet: `0 ≤ gas_price ≤ 10,000`|
| `gas_currency_code`: This is the currency of the transaction fee (which is at most `gas_price * max_gas_amount`) charged to the client.  | The `gas_currency` must be a registered currency on-chain (`XUS` on testnet), and must be one of the held currencies of the sending account. E.g. setting the `gas_currency` to "Coin3" would cause the transaction to be rejected since Coin3 is not a registered currency on-chain, and the sending account does not hold that currency.|

You can learn more about gas and how it works [here](core/gas.md).

### What are Events?
Each transaction is designed to emit any number of events as a list. An aborting transaction never emits events, so you can use events to confirm if a transaction has been successfully executed.

For example, a peer-to-peer payment transaction emits a `SentPayment` event for the sender’s account and a `ReceivedPayment` event for the recipient account. The `SentPayment` event allows the sender to confirm that the payment was sent from their account, while a `ReceivedPayment `event allows the recipient to confirm that a payment was received in their account. Events are persisted on the Diem Blockchain and you (as a Regulated VASP) can use these events to answer your queries.

##### Event Structure

There are a number of events that can be emitted from a transaction. The primary ones that you should be aware of are the `SentPayment`, and `ReceivedPayment` events.  A `ReceivedPayment` event contains the amount received and currency, the sending address, and a metadata field that contains any transaction specific information that the sender has added to the payment, subject to certain limitations specified in the Participation Agreement and DPN Rules. Likewise, a `SentPayment `event contains the amount sent and currency, the receiving account address, and any metadata that the sender has added to the payment.

The exact structures of these events are as follows:

**ReceivedPayment**

| Name | Type | Description |
| -------- | -------| ------------------- |
| `type` | string | Constant string "receivedpayment" |
| `amount` | Amount | Amount received.|
| `sender` | hex string | Hex-encoded address of the account that the money was received from. |
| `metadata` | hex string | Optional field that can contain extra metadata for the event, subject to certain limitations specified in the Participation Agreement and DPN Rules.|

**SentPayment**

| Name | Type | Description |
| -------- | -------| ------------------- |
| `type` | string | Constant string "sentpayment" |
| `amount` | Amount | Amount sent. |
| `receiver` | hex string | Hex-encoded address of the account that the payment is being sent to.|
| `metadata` | hex string | Optional field that can contain metadata for the event.|

where the amount structure is:

**Amount**

| Name | Type | Description|
| -------- | -------| ------------------- |
| `amount` | u64 | Amount in base currency units (e.g. microdiem).|
| `currency` | String | Currency code (e.g. `XUS`) |


More information on event structures, and how they can be queried and the surrounding data in the JSON responses can be found [here](https://github.com/diem/diem/blob/main/json-rpc/json-rpc-spec.md).

To check for new transactions posted to your account, you need to [query the blockchain](core/query-the-blockchain.md) using the JSON-RPC endpoints.

* If you are sending the transaction, you query for the transaction’s sequence number.
* If you are receiving the transaction, you query for the ReceivedPaymentEvent event.

## Accepting Direct Payments

#### Checkout Experience

When the Diem Payment Network launches, we expect that wallets will support a basic set of payment flows that resemble peer-to-peer transactions. Accordingly, the initial range of merchant checkout options will be limited to direct payments: single point-in-time transactions with a known amount and currency type.

To provide an interoperable checkout experience, a merchant service provider will need to share payment information with the end user. This can happen through a generated QR code, copy-pastable URI, or mobile deep link.


![Figure 2.0 How checkout works for direct payments](/img/docs/direct-payments.svg)

This “payment context” includes:
* Fully qualified address: stable on-chain address and unique, generated subaddress
* Payment amount in microunits
* Currency code

More information about payment request URI serialization can be found [here](https://dip.diem.com/dip-5/).

After the RegulatedVASP providing the relevant consumer with a wallet receives the “payment context,” it can construct a pre-populated payment for the user to authorize.


When the user authorizes their wallet to pay the merchant per the shared “payment context,” their wallet will go through a similar sender flow to a peer-to-peer payment. A transaction is committed directly on-chain as long as the amount doesn't exceed the Travel Rule threshold. If the Travel Rule goes into effect, the payment will first be preflighted through the off-chain protocol, before being committed on-chain.

More information about the off-chain protocol can be found [here](https://dip.diem.com/dip-1/).

#### Detecting Purchases
A merchant service provider can interface with a full node to track emitted events for their on-chain accounts. If they see that they have received funds, they can examine the accompanying subaddress to route the funds internally. Since the subaddress will be unique for each transaction, they can determine who the buyer was. In other words, the merchant service provider can connect the funds received to a checkout session and signal confirmation to the end user.

More information about events can be found [here](/core/events.md).


#### Handling Refunds
In some cases, a merchant may want to issue a refund to a customer. For instance, if the merchant receives duplicate payments or a payment to an invalid subaddress. Additionally, merchants may want to refund a user upon a return or other customer support inquiry.

Refunds on the DPN resemble any other peer-to-peer transaction. A merchant service provider would need to construct a transaction script on behalf of the merchant, and submit it to the original customer. These transactions are subject to the Travel Rule controls and will require off-chain preflighting if the amount exceeds the Travel Rule threshold.

Unlike other transactions, refunds will contain a pointer to the original transaction that they correspond to. If the transaction exceeds the Travel Rule threshold, the `original event reference id` is included in the off-chain payload. Otherwise (ie. in the non-Travel Rule case), the `original event sequence number` is sent in the on-chain body of the refund transaction. Wallets that receive refunds can use the reference to the original transaction to provide additional context to the inbound funds.

More information about refunds can be found [here](https://drive.google.com/file/d/1YUEtAqd0N5dl2vg5EgEQhrVQKNN0OhoI/view?usp=sharing). Additional information about transaction serialization can be found [here](https://dip.diem.com/dip-4/).


###### tags: `merchant`
