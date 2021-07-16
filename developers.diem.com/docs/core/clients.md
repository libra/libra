---
id: clients
title: Clients
sidebar_label: Diem Clients
---

A Diem client is a piece of software that has the capability to interact (via FullNodes) with the Diem Blockchain (referred to in this page as blockchain). It can allow a participant to submit and sign transactions and query the blockchain for the status of a transaction or account.

Clients communicate with FullNodes exclusively using a JSON-RPC interface. SDKs implement and interact with the network via the JSON-RPC interface. Learn about available Diem SDKs [here](/docs/sdks/overview).

You can interact with the blockchain in a language of your choice using the different Diem SDKs we have available. Learn how you can do this in the [My First Client tutorial](/docs/tutorials/my-first-client). If there is no SDK for the language of your choice and you want to interact directly with the blockchain using your own client implementation, follow the steps in this tutorial.

All SDKs are built on the [JSON-RPC API](https://github.com/diem/diem/blob/main/json-rpc/json-rpc-spec.md). Advanced users may implement their own if an SDK is not available in the preferred language.


###### tags: `core`
