---
id: develop-reference-wallet
title: 'Reference Wallet Development'
sidebar_label: Set up and Develop

---



## Set up the Reference Wallet

To set up your environment or deploy the Reference Wallet, please refer to the latest information in the Backend README [here](https://github.com/diem/reference-wallet/tree/master/backend#getting-started).

The Reference Wallet is available as a web and mobile application.

## Login and authentication

Login and authentication deals with all logic related to a user creating a new account, signing in, logging out, and keeping a session.


#### Implementation

The main features of the login and authentication implementation in the Reference Wallet include:


* User registration
  - During registration, the user will choose a unique username and password, and provide information such as name, DOB, and other KYC related information.
  - Each user has a unique user ID (integer) and a unique username (string).
* Sign in and sign out
  - User signs in with the username and password.
  - The password is hashed using a simple Python hashlib.
  - Each sign in generates a new user session token. And, each sign out deletes the user session token.
* Session management
  - When a user creates a new account or signs in, the client is provided with a bearer token. This bearer token is a UUID string and will expire after a certain period of time for user security.
  - The bearer token is stored in the token database, along with the user ID and expiration time.
  - Whenever the client makes an API call, they need to have the bearer token in the request header. The validity of the token is checked with every call.
  - The token is valid if it exists in the token database and if it has not expired.
  - If the token has expired, an unauthorized error is returned in the API call.
  - Each valid API call extends the expiration of the token.


#### Extend functionality

* The bearer token is just one way of doing session management. Other forms of authentication can be used to make server calls more secure.
* Login and authentication can be made more secure by incorporating two-factor authentication.


#### GitHub repository
https://github.com/diem/reference-wallet/blob/master/backend/wallet/services/account.py




## Custody module

The Custody module handles crafting and signing transactions. Once a VASP is ready to settle a transaction on-chain, the Custody module needs to craft the transactions, sign with its private key, and return the signed transaction. The Custody module should be the only service that has access to the wallet’s private key.

#### Implementation

For the local development of the Reference Wallet, the private key is randomly generated on instantiation of the wallet app. It can also take a private key via environment variable as _CUSTODIAL_PRIVATE_KEY_.

For this demo wallet, we do not show an implementation of providing secure storage of private keys. Custody uses pydiem library to create signed transactions.

#### Extend functionality

A robust custody solution should be plugged in for a production-level product.




## Compliance module


> Note: This section will be updated with the next version of this document.


VASPs, including custodial wallet providers operating on the Diem Payments Network ("DPN"), will be required to maintain compliance programs and to comply with applicable anti-money laundering ("AML") and economic and financial sanctions ("sanctions") laws as well as standards established by Diem Networks. When a new user wishes to create a Diem wallet account, a VASP, pursuant to its compliance program would assess the AML and sanctions risks of maintaining a business relationship with the user. The compliance module assesses these risks at the time of customer onboarding and on an ongoing basis through Know Your Customer (KYC) procedures and transaction monitoring.


### KYC (Know Your Customer)

KYC procedures are intended to allow the wallet provider to identify, and confirm if required, the identity of a prospective user and to assess the AML and sanctions risk of the user at onboarding and on an ongoing basis.

The nature of a wallet provider’s KYC assessment is governed by applicable AML and sanctions laws and regulations, and may differ by jurisdiction and the specific policies and procedures established by the VASP with respect to AML and sanctions compliance, including in the context of the customer onboarding process.

The Reference Wallet demonstrates an example of a risk-based KYC procedure that requests the user to provide personal identification information such as:

* First and last name
* Date of Birth
* Nationality
* Address
* Government issued identification document as a proof of nationality

The type of information requested of a user, including follow-up information or documentation, may vary depending on certain risk factors (e.g., customer geography, expected activity, and product type).

The wallet provider must assess the risk of the client and ensure all the required regulatory checks take place. The wallet provider may undertake these checks itself or may involve one or more service providers. Certain checks may be automated while others may be manual.

In this demo, the user data is sent to an external KYC provider to assess the user. In the ordinary course, such an external provider would undertake certain checks of the prospective user. Examples of such checks include sanctions screening, negative news screening, black-listed country screening, and document verification. Based on this information the provider would assign a risk rating that would inform the wallet provider’s decision as to whether to onboard the customer or whether certain controls (e.g., product or transaction limitations) may be appropriate in light of the user's risk.

After a user has been onboarded, the wallet provider, pursuant to relevant laws and regulations, Diem Network standards, and its compliance program, must continue to assess the risk related to maintaining a business relationship with the user.

> **Note**: The compliance processes depicted in this document are for demonstration purposes only and do not reflect the specific compliance obligations of VASPs under applicable regulatory frameworks, their compliance programs, and/or standards imposed by Diem Networks.
>
>  In this project, the KYC provider is not actually checking the user, and all users are automatically approved.

### Transaction monitoring

Wallet providers generally must also conduct transaction monitoring on an ongoing basis to prevent their services from being used to conduct or facilitate illicit activity, including money laundering, terrorist financing, and/or violation of applicable sanctions. Transaction monitoring procedures must be designed to comply with relevant laws and regulations and the standards of Diem Networks, and should be commensurate with a wallet provider’s risk profile.

In a real-world scenario, transaction monitoring would generally encompass both inbound and outbound payments. Examples of behaviors that transaction monitoring may seek to identify include:

* Attempts to circumvent account restrictions or network limits
* Unexpected behaviors
* Indicators of suspicious activity
* Travel Rule compliance (the Reference Wallet does not simulate the Travel Rule)
* Sanctions compliance

As with KYC, the wallet provider may conduct transaction monitoring itself (e.g., through a financial intelligence function) or engage a service provider to assist in this process. In any case, the wallet provider remains ultimately responsible for its compliance with applicable laws and regulations and Diem Network standards.

In a real world scenario, transaction monitoring may lead to various outcomes depending on the activity identified. These include but are not limited to:

* Approval of a transaction
* Denial of a transaction
* Request additional data from the user
* Restricting or limiting a user account
* Blocking a transaction or user funds, if required by law
* Making required reports to relevant regulator(s) (e.g., suspicious activity reports)

In a real-world situation, a wallet provider conducts continuous monitoring of its customers through periodic and risk-based KYC refreshes and transaction monitoring procedures. In addition, transactions on the LPN will be subject to Diem Networks' Financial Intelligence Function ("FIF") network monitoring. This network-wide monitoring, together with transaction monitoring undertaken by LPN service providers, will seek to detect illicit activity, including with respect to money laundering, terrorist financing, and other potentially evasive uses of the platform. The FIF will report identified activity to relevant regulators and law enforcement, where appropriate.

In this demo project, we use an external risk provider as a placeholder for transaction monitoring and regulatory checks. The service will always approve the transactions since no actual checks are performed, and since no specific reviews are actually being performed and no activity is actually being monitored in the demo project, no payments will be blocked, denied, or reported.

### Fraud prevention

As a custodial wallet, all blockchain transactions must use the wallet provider signature. When  a transaction is approved on-chain, there is no way to reverse it. The wallet provider should take whatever measures it determines appropriate to ensure that the transaction request was made by the user and is not a fraud attempt, before submitting a blockchain transaction.

In the Diem Payment Network, the transactions are done between VASPs and then allocated to the end users. A fraudulent transaction can be reversed if the VASPs recognize it as such.




## Risk module

> Note: This section will be updated with the next version of this document.

### Implementation

The Reference Wallet has a very simple risk check that happens synchronously with each transaction; it is a mocked out API that is simply based on the amount of the transaction. In production, the VASP will need to determine the risk check that is necessary to comply with AML and fraud prevention.




## Transaction workflows

A VASP needs to be able to handle the following on-chain transactions:

* Send and receive funds internally within the same VASP network.
* Send and receive funds externally to a user of another VASP.

The Reference Wallet shows the workflow of each of these transaction types.

### Implementation

#### Internal P2P transfer

* Internal P2P transfer entails a simple balance check and storage update, and does not require any on-chain settlement.

#### External P2P Transfer

* External P2P transfers are transactions between users in different VASP networks. This type of transaction requires an on-chain settlement. For any amount less than the amount needed for compliance, a VASP can directly send the transaction on-chain without doing any KYC validation.
* Uses pydiem.


### Extend functionality

Currently the Reference Wallet only implements three types of transactions. However, as the scope increases, other types of transactions, such as merchant pull request flow, could be added to extend the functionality of the Reference Wallet.






## Storage module

The Reference Wallet uses SQL as its data store, and SQLAlchemy as the Python toolkit and object relational mapper. Storage is part of the Wallet module, and consists of models and utils. In wallet/storage, models.py defines the tables and utils are divided into respective modules based on which object the util reads or modifies.


### User

User table stores all information related to the user’s identity, registration, and KYC information. On user registration, username, and password information are stored. KYC information such as full name, dob, address, and phone number are also stored during the registration process.


### Account

While the user table deals with a user’s identification and login information, the account table purely deals with the user’s transactions. Each user has an account, in which all transactions and balances are stored. There is a special case for the admin user, who does not have any corresponding account. Currently each user has a single account, but the wallet could be extended for a user to hold multiple accounts. Another special case is the inventory account, which doesn’t have any corresponding user.


### Transaction

Transactions table stores all the metadata of sending or receiving transactions. Depending on the transaction type, each transaction object may not have certain rows filled. For example, in the case of an in-network transaction, blockchain_version and sequence will be None since an in-network transaction does not require a blockchain transaction. In the case of an external transaction, either the source_id or the destination_id may be missing, since we will not have an ID for the external user.


### Transaction log

Transaction log table stores the status of transactions as they get processed. These logs can be exposed to the user to show which stage a transaction is at. Example logs include “Settled on-chain” and “Transaction complete.”


### Subaddress

Subaddress is the internal user address of the Reference Wallet. A subaddress is an 8-byte string that is meant to be one-time use. A new subaddress is generated each time a user generates a receiving address to send to a sender.


### Token

Token table stores user session tokens for session authentication. When a user creates an account or signs in to their account, the server generates a token and stores it in the token table along with user_id and expiration_time. Whenever a user makes an API call, we check if the token exists in the table and that expiration_time has not passed.


### Order

> Note: This section will be updated with the next version of this document.

### Execution log

The execution log table is used for debugging and the data is not exposed to the user. Execution logs can easily be added in any function using add_execution_log().






## Service API

Service APIs are a set of backend APIs that are organized in terms of high-level wallet functionalities. They are defined in the webapp layer, and the frontend uses these APIs to communicate with the backend. The service APIs are RESTful APIs that are divided into user, account, CICO, and admin.

Docs can be generated locally using SwaggerUI. Instructions for how to get that set up can be found in the backend README under “Getting Started”, linked [here](https://github.com/diem/reference-wallet/tree/master/backend#getting-started).

### User

User APIs handle user creation, and information management and updates.

![Figure 1.0 User API methods](/img/docs/service-api-user.svg)

### Account

Account APIs deal with an account’s address and transactions management.

![Figure 1.1 Account API methods](/img/docs/service-api-account.svg)

### CICO

CICO handles all cash-in and cash-out flows, including getting rates and executing a given quote.

![Figure 1.2 CICO API methods](/img/docs/service-api-cico.svg)

### Admin

Admin APIs fetch admin user account information and have debt settlement logic.

![Figure 1.3 Admin API methods](/img/docs/service-api-admin.svg)





## PubSub

> Note: This section will be updated with the next version of this document.

PubSub allows us to continually poll the blockchain and respond to events on-chain. Specifically, for the Reference Wallet, we’re listening to payments made to the VASPs’ public on-chain addresses.

### Implementation

Our *pubsub* module is based on an open source project called *pubsub_proxy*, a lightweight wrapper around *pydiem*. For the Reference Wallet, we redirect all events delivered by pubsub_proxy directly to our wallet service’s *on-chain* module for internal processing.

PubSub depends on the *PUBSUB_ADDR* environment variable.


### Extend functionality

*Pubsub_proxy* is designed to be extensible. You can extend *BasePubSubClient* to determine how to handle incoming payment events.





### Liquidity inventory setup

The liquidity inventory setup is part of the backend startup sequence. At start, an internal inventory user is created. This internal user manages the balance of the internal custody wallet inventory. After its creation, the backend [“buys” its initial Diem Coins from the external liquidity provider](wallet-app/intro-to-drw.md#diem-coin-sourcing). The custodial wallet provider directs the liquidity provider to send purchased Diem Coins to the custody wallet’s Diem blockchain address.

From this point, the custodial wallet service can engage in transfers between its inventory account and the wallet user accounts to transfer the requested funds.


### Add, withdraw, or convert flows

A wallet user can select the following transfer types in the reference wallet



* Add funds
* Withdraw funds
* Convert funds


#### Add funds

This transfer type is when a user wants to add funds to their wallet balance.

For example, if a user wants to add 100 Coin1 and clicks “Add”.



* The frontend will ask the backend for conversion rates, which will then be presented to the user. For this example, _100 Coin1 will be added in exchange for 100 USD_.
* When the user is ready to proceed, the frontend will ask for a final quote from the backend and will present the final terms to the user.
* Once the user approves, the frontend will send an execute quote request to the backend.
* The backend API will create an order with the order details and will then execute the process order workflow. The order will be dispatched and the correct workflow handler will be triggered.
* The add/withdraw funds workflow will try to charge/refund the user payment method according to the order details.
* If that succeeds, an internal network transaction is initiated to transfer the Diem Coins from the user account to the custody wallet inventory account or vice versa.
    * For purposes of the reference wallet, this transfer is not a blockchain transaction (i.e., it is an off-chain transaction) rather it updates the internal balance of the user.
    * Wallets may choose to structure their accounts differently than demonstrated here.
* After the internal transfer is complete, the wallet has to rebalance the inventory. This is the **cover process**.

Usually, the cover process is independent of the order execution process and contains elements like exposure management, risk management, trading strategies, spread management, and more.

The cover process in the Reference Wallet is executed back-to-back with the order execution. In our example, the backend will be covered by trade with the liquidity provider.


##### Example Cover process

The wallet uses the cover process to balance its inventory after transactions with user accounts. In this example, the wallet exchanges 100 USD for 100 Coin1 from the liquidity provider to balance its inventory.

* The wallet requests the liquidity provider to transfer 100 Coin1 to the wallet inventory account as part of the trade **execution**. In the same step, the wallet also **commits** to sending the liquidity provider 100 USD in exchange.
* Once the wallet executes the quote to buy 100 Coin1 from the liquidity provider, the provider logs an outstanding debt of 100 USD for the wallet and posts a Diem Blockchain transaction sending 100  Coin1 to the wallet inventory. The wallet will then have to settle this outstanding debt with the liquidity provider. In the Reference Wallet, you can simulate settling outstanding debts using the admin dashboard.


#### Withdraw funds

In the withdrawal process, things work the other way around. The user payment method is refunded, an internal transaction moves Diem Coins from the user account (off-chain) to the inventory account, and then in the cover process Diem Coins are traded in exchange for fiat back-to-back with the liquidity provider.


#### Convert funds

For the purpose of simplifying this Reference Wallet, the conversion between Diem Coins of different currencies is represented by transactions between the custodial wallet and the user and reflected by internal transfers (off-chain) between the user account and the inventory account.


### Fiat settlement flow

Settlement flow is not implemented at this point. This is the process where the liquidity provider and custody wallet settle the fiat balances owed to each other by passing a reference for fiat wire transfers between the custody wallet bank account and the liquidity provider bank account and vice versa to settle the debt. The settlement interface and internal structures are demonstrated in the liquidity provider-client implementation.





### Main components

#### API methods

These provide the backend interface for frontend client requests. All calls related to liquidity are handled in the dedicated Flask blueprint under wallet/routes/cico.py.

| Methods                                           | Description                                                  |
| ------------------------------------------------- | ------------------------------------------------------------ |
| `GET /account/rates`                              | Return to the client all available conversion rates between currency pairs |
| `POST /account/quotes`                            | Request for a quote for a currency pair exchange. Return a quote id. |
| `POST /account/quotes/<quote_id>/actions/execute` | Execute the quote. At the end of execution, user balance will reflect the currency exchange. |
| `GET /account/quotes/<quote_id>`                  | Return the quote execution status.                           |



#### Liquidity module

This module is located under `wallet/liquidity.`

Contains all the utilities for rate calculation and client order processing, as well as a client to communicate with an external liquidity provider.

#### Client

The client simulates a client SDK that interacts with an external liquidity provider. It allows its user to ask for quotes from the liquidity provider, execute a trade with the liquidity provider on a given quote, and demonstrate the fiat settlement interface.

#### Order service

Contains the code that handles the end-user order creation, status updates, and utility functions that contain the logic required for the order execution and cover processes.

#### Rate service

A utility code that demonstrates rate calculation for different currency pairs with a fixed conversion table.

#### Exchange rates

Exchange rates are pre-defined. The liquidity provider supports a predefined set of currency pairs with fixed conversion rates. The Reference Wallet supports a richer set of conversions by managing a conversion table which describes the steps required to convert between currencies that do not have a direct conversion between them.



## Localization

The wallet UI is fully translatable using standard React i18n library [react-i18next](https://react.i18next.com/). All texts are mapped in JSON files located at `frontend/src/locales/LANGUAGE`.

To generate new translations, a script is available for auto-generating new translations using a third-party translation service or exporting all existing text into a CSV file for manual translation. Located at `scripts/generate_i18n.py` are usage example for translating from English to Spanish: `./scripts/generate_i18n.py -s en -d es -a` this will use EN JSON files located at `frontend/src/locales/en` and generate new JSON files at `frontend/src/locales/es`. Instructions for using the newly generated files will be shown upon completing these steps:

1. Add `import ES from "./es";` to `frontend/src/locales/index.ts`

2. Add `es: ES;` to the default Resource object in there


To extract translations into a CSV file for manual translations, you can use the export flag:
`./scripts/generate_i18n.py -s en -d es -e ./english_texts.csv`

To import manually translated CSV you can use the import flag:
`./scripts/generate_i18n.py -s en -d es -i ./english_texts.csv`





## Reference Wallet API Docs

<iframe src="https://demo-wallet.diem.com/api/apidocs/" width="100%" height="800px"></iframe>




###### tags: `wallet`
