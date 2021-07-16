---
id: events
title: Events
sidebar_label: Events
---

Events are Move data that are emitted during the execution of a transaction on the Diem Blockchain. For example, whenever a payment is sent or received on-chain, the transaction will emit relevant data using the `SentPaymentEvent` and `ReceivedPaymentEvent`. This data is stored in the EventStore, which is part of the Diem Blockchain’s ledger state. You can query the EventStore to get proof of executed transactions on-chain.

As shown in the following diagram:

* Events are grouped into “**event streams,**” which are append-only vectors of ContractEvent payloads.
* Each stream is associated with a key value, which is a globally unique 40-byte array that is defined when the stream is created.
* The entries in an event stream are assigned sequence numbers beginning from zero.

  ![Figure 1.0 EventHandle and event streams in the Diem Framework](/img/docs/events-fig1.svg)
  
* A ContractEvent payload contains the event key, the sequence number, and a serialized Move value, along with a tag to identify the type of that value. Different kinds of events are distinguished by the Move value types, such as `SentPaymentEvent` or `ReceivedPaymentEvent`, which are emitted to the event streams.

* Event streams are referenced from the StateStore via EventHandle Move resources. An EventHandle contains the event key and the number of events in the stream. (This count is always equal to the biggest sequence number for the events in the stream). An EventHandle resource is typically embedded inside other Move resources to record related events. For example, every DiemAccount resource contains a sent_events EventHandle for a stream of SentPaymentEvents and also a received_events EventHandle for a stream of ReceivedPaymentEvents.

The details of the event implementation in Move are specified by the Event module in the Diem Framework. The views of event information from JSON-RPC are often presented somewhat differently than underlying implementation. For example, EventHandles are typically displayed as only the key values, e.g., sent_events_key instead of a sent_events EventHandle structure containing the key. The rest of this section shows examples of events as they are viewed through the JSON-RPC interface.

## Events available in the system

The Diem Framework uses a number of different kinds of events such as for payments, minting/burning, and system operations. A detailed list of the event types accessible from JSON-RPC is available in the [JSON-RPC documentation](https://github.com/diem/diem/blob/main/json-rpc/docs/type_event.md).

There are two types of events related to payment transactions. Whenever a payment transaction is committed, it emits the following events:

* A `SentPaymentEvent` to the sender’s SentPaymentEvent stream
* A `ReceivedPaymentEvent` to the recipient's ReceivedPaymentEvent stream

Both `SentPaymentEvent` and `ReceivedPaymentEvent` have the same structure:

| Field Name | Type                                                         | Description                                                  |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| amount     | [Amount](https://github.com/diem/diem/blob/main/json-rpc/docs/type_amount.md) | Amount received from the sender of the transaction           |
| sender     | string                                                       | Hex-encoded address of the account whose balance was debited to perform this deposit. If the deposited funds came from a mint transaction, the sender address will be 0x0...0. |
| receiver   | string                                                       | Hex-encoded address of the account whose balance was credited by this deposit.<br /> |
| metadata   | string                                                       | An optional field that can contain extra metadata for the event. This information can be used by an off-chain API to implement a sub-addressing scheme for a wallet. |



Minting and burning transactions produce events that are associated with a specific currency type. Each registered currency has a `CurrencyInfo<CoinType>` resource on chain, which contains four related event streams:

* `BurnEvent`
* `PreburnEvent`
* `CancelBurnEvent`
* `MintEvent`

There are also several events related to system-level operations, for example:
* `UpgradeEvent` — when a special system maintenance WriteSet transaction is applied
* `NewEpochEvent` — when an on-chain configuration is modified
* `NewBlockEvent` — when a new block of transactions is added to the Diem Blockchain

## How to query events
There are several JSON-RPC APIs associated with events:
* The get_account_transaction, get_account_transactions, and get_transactions APIs each have an option to also return the events emitted by the transactions.
* get_events returns the events from a specific event stream.


### Get `SentPaymentEvent` for an account

This example demonstrates how to query a `SentPaymentEvent` for an account. In this example, account 0x996b67d has two event streams, with three sent payments and two received payments:![Figure 1.1 Example event streams for a Diem Account](/img/docs/events-fig2.svg)

1. The first step is to find the event key for the account’s `SentPaymentEvent` stream. We can send a [get_account](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_account.md) query to the JSON-RPC endpoint to get the state of that [account](https://github.com/diem/diem/blob/main/json-rpc/docs/type_account.md), including two event keys: one for the `SentPaymentEvent` stream (the sent_events_key field) and one for the `ReceivedPaymentEvent` stream (the received_events_key field). The response will look like the following:

    ```
    {
      "diem_chain_id" : 2,
      "jsonrpc" : "2.0",
      "diem_ledger_timestampusec" : 1597084681499780,
      "result" : {
       ...
       "received_events_key" : "00000000000000001668f6be25668c1a17cd8caf6b8d2f25",
       "sent_events_key" : "01000000000000001668f6be25668c1a17cd8caf6b8d2f25",
       ...
      },
      "id" : 1,
      "diem_ledger_version" : 1303433
    }
    ```


    This query is only needed once per account because the event     keys for the account’s event streams will never be modified.

2. The next step is to use the [get_events](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_events.md) API to fetch the event details. We can specify in the JSON-RPC query to fetch one event beginning with sequence number two from the sent_events_key event stream. The response will look like the following:

    ```
    {
     "id": 1,
     "jsonrpc": "2.0",
     "diem_chain_id": 2,
     "result": [
      {
       "data": {
        "amount": {
         "amount": 200,
         "currency": "LBR"
        },
        "metadata": "",
        "receiver": "280081f",
        "sender": "996b67d",
        "type": "sentpayment"
       },
       "key": "01000000000000001668f6be25668c1a17cd8caf6b8d2f25",
       "sequence_number": 2,
       "transaction_version": 106495
      },
    }
    ```


Note that the JSON-RPC view of the event data is a bit different from the underlying `SentPaymentEvent`, which has a single payee field instead of both receiver and sender.


###### tags: `core`