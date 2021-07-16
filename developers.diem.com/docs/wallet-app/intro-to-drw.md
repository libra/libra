---
id: intro-to-drw
title: 'Reference Wallet Concepts'
sidebar_label: Wallet Concepts
---

The Reference Wallet is meant to help developers learn how a wallet could work on the Diem Blockchain. Once you [set up and deploy the Reference Wallet locally](wallet-app/develop-reference-wallet.md), you can test and understand the concepts behind wallet development on the blockchain. The goal of the reference wallet project is to help you determine how to implement, customize, and integrate your wallet on the Diem Payment Network.

We’ve also created a public, online demo version of the Reference Wallet (the “Public Demo Wallet”). This [set up and deploy the Reference Wallet locally](wallet-app/develop-reference-wallet.md) does not have all the functionalities of the Reference Wallet, and is only meant to provide a demonstration of basic wallet use cases on testnet.

The Reference Wallet and Public Demo Wallet include various references to transacting in Diem Coins.  All such transactions are simulations and these simulated Diem Coins can be deactivated by the Diem Association at any time.  In addition, these simulated Diem Coins will not function, or in any way be usable or recognized, on mainnet.


> **Note:** Custodial wallet services like holding Diem Coins for customers, exchanging one type of Diem Coin for another, transferring customer Diem Coins to other users (whether in the same wallet or others), and exchanging Diem Coins for cash all potentially money transmission or money services business activities, depending on the state/federal jurisdictions involved.
>
> The functions described in this document may require the service provider to be licensed in the jurisdictions in which it operates and, to operate on the Diem Payment Network, it will need to be a Regulated VASP reviewed and onboarded by Diem Networks.

### The Lifecycle of a transaction

Before you get started with the Reference Wallet, get familiar with how transactions are sent and received on the Diem Blockchain.

When you submit a transaction to the Diem Payment Network, you are cryptographically signing a transaction script and then waiting (by listening to the event stream) for consensus from validators. The diagram below shows the flow of a transaction once it’s been submitted. Learn more about this flow [here](core/life-of-a-transaction.md).


![Figure 1.0 Lifecycle of a transaction](/img/docs/validator.svg)

## Wallet Architecture


The Reference Wallet is structured into three main modules:



### Wallet

The Wallet module manages the core functionality of a wallet, such as account creation and management, balance updates, as well as the business and compliance logic of sending and receiving transactions. This module has been developed so that the Reference Wallet is custodial.



### Web app

The Reference Wallet uses Flask as its web framework. The web app provides a RESTful API that is divided into user, account, CICO, and admin.



### PubSub

PubSub allows you to continually poll the Diem Blockchain and respond to events on-chain. In the Reference Wallet, we listen to the event stream to track payments made to the public on-chain address of a VASP (Virtual Asset Service Provider) or a wallet developer.


## Diem Coin Sourcing

Generally, a custodial wallet service will be expected to buy and sell Diem Coins for fiat currency in the market, from a variety of service providers. This type of service is beyond the scope of the Reference Wallet.

The Reference Wallet models this approach by 1) having an internal liquidity service that manages its liquidity processes and 2) arrangements with external liquidity provider stubs to simulate Diem Coin order fulfillment by a third-party service provider. This model facilitates a custodial wallet providing a fluid and smooth customer experience, through which a customer can purchase Diem Coins for fiat through the custodial wallet interface, without having to separately engage with the fiat-Diem Coin service provider.

![](/img/docs/diem-c-sourcing.svg)



### Inventory management

A custodial wallet holds Diem Coins in an internal inventory account. When a customer buys or sells Diem Coins with the custodial wallet service, the transaction is performed internally against the custodial wallet service’s inventory account. In order to fulfill customer purchase or sale orders on an ongoing basis, a custodial wallet has to continuously manage its internal inventory, replenishing it or reducing it as needed.

Specific liquidity management strategies may vary according to each business.

* For example, Diem Coin inventory management can be done in a **one-to-one** manner. This means for each customer transaction, a custodial wallet service will offset increases or decreases to its inventory with sales or purchases from a third-party liquidity provider.
* Another approach is to manage Diem Coin inventory on a daily basis.  A custodial wallet service would net all daily customer transactions and engage in one (or a few) transactions with a third-party liquidity provider to maintain desired Diem Coin inventory levels.


For the sake of this demonstration, the Reference Wallet implements **the one-to-one** approach.



#### Price Quotation Displays

Diem Coin prices are displayed in the Transfer section (Add, Withdraw, and Convert functions) of the Reference Wallet. Diem Coin price quotes from a custodial wallet to its customer aren’t expected to be changed very often. But as wallet customers will expect their transactions to be executed at the quoted rate as displayed, the wallet provider should try to limit the prices or spreads at which the transactions occur. While the front-end service is running, it polls for rates every few seconds. The price calculation used when a user wants to buy Diem Coins is based on these recently received rates. This way the price should not fluctuate too much while filling the order or updating the amounts displayed on the screen. Additionally, when a user confirms the simulated sale to convert Diem Coins to fiat or vice versa, the client validates that the price does not exceed boundaries (the boundary check is performed by the backend system), and then requests for execution.

Because quotes may last for a short time, customers may find it helpful for the wallet to display a benchmark rate for each currency. Such a rate would not be intended to bind the wallet or the third-party liquidity provider that provides the benchmark price, but instead gives an indication of the exchange rate in real time.



### Architecture

The use cases handled by the Reference Wallet service are:

1. Add funds: This simulates the purchase of Diem Coins in exchange for a fiat currency.
2. Withdraw funds: This simulates the withdrawal of fiat currency in exchange for the simulated sale of Diem Coins.
3. Convert: This simulates a conversion between the different Diem Coins.

In the Add Funds use case, the user’s simulated credit card or bank account is charged the fiat currency amount to simulate the purchase. In the Withdraw Funds use case, the user’s simulated credit card or the bank account is credited to simulate the withdrawal.

