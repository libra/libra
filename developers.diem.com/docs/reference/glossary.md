---
id: glossary
title: Glossary
sidebar_label: Terminology
---

## A

---

### Accumulator Root Hash

- An **accumulator root hash** is the root hash of a [Merkle accumulator.](https://eprint.iacr.org/2009/625.pdf)

### Access path

- An **access path** specifies the location of a resource or Move module within a specific account.
- In a state of the Diem Blockchain, an account is represented as a map of access paths to values. The Move VM deserializes this representation into modules and resources.
- Clients can use access paths to request a resource or a specific piece of data stored inside a resource.

### Account

- An **account** in the Diem Blockchain is a container for an arbitrary number of [Move modules](#move-module) and [Move resources](#move-resources). This essentially means that the state of each account is comprised of both code and data.
- The account is identified by an [account address](#account-address).

### Account Address

- The address of a Diem payment system account is a 16-byte value. Users can claim addresses using digital signatures. The account address is derived from a cryptographic hash of a user’s public verification key concatenated with a signature scheme identifier byte. The Diem payment system supports two signature schemes: Ed25519 (for single-signature transactions) and MultiEd25519 (for multi-signature transactions). To sign a transaction sent from an account address, the user, or the custodial client representing the user, must use the private key that corresponds to that account.

### JSON-RPC Service

- The JSON-RPC Service component is the external interface of a Diem node. Any incoming client request, such as submitted transactions or queries, must first go through the JSON-RPC Service. A client needs to go through the JSON-RPC Service component to access storage or any other component in the system. This filters requests and protects the system.
- Whenever a client submits a new transaction, the JSON-RPC Service passes it to [mempool](#mempool).


### Authentication Key

- An **authentication key** is used to authenticate the cryptographic key used to sign a transaction.
- It is a piece of data stored in the user's account on the blockchain.
- Users can rotate their signing key by rotating their authentication key.

## B

---

### Block

- A **proposed block** on the Diem Blockchain is an ordered list of zero or more transactions proposed by the consensus leader for validators to reach agreement on execution through consensus.
- A **committed block** is an ordered list of zero or more transactions from a proposed block for which agreement on execution has been reached through consensus and which is recorded to the Diem Blockchain.

### Blockchain

- A **blockchain** is a distributed public ledger.
- The Diem Blockchain is a single data structure that records the history of transactions and states over time.

### Byzantine (Validator)

- A **validator** that does not follow the specification of the consensus protocol, and wishes to compromise the correct execution of the protocol.
- BFT algorithms traditionally support up to one-third of the algorithm's voting power being held by Byzantine validators.

### Byzantine Fault Tolerance (BFT)

- **Byzantine Fault Tolerance** (BFT) is the ability of a distributed system to provide safety and liveness guarantees in the presence of faulty, or “[Byzantine](#byzantine-validator),” validators below a certain threshold.
- The Diem Blockchain uses DiemBFT, a consensus protocol based on [HotStuff.](#hotstuff)
- BFT algorithms typically operate with a number of entities, collectively holding N votes (which are called “validators” in the Diem network’s application of the system).
- N is chosen to withstand some number of validators holding f votes, which might be malicious.
- In this configuration, N is typically set to 3f+1. Validators holding up to f votes will be allowed to be faulty &mdash; offline, malicious, slow, etc. As long as 2f+1 votes are held by [honest](#honest-validator) validators, they will be able to reach consensus on consistent decisions.
- This implies that BFT consensus protocols can function correctly, even if up to one-third of the voting power is held by validators that are compromised or fail.

## C

---

### Client

A **client** is a piece of software that has the capability to interact with the Diem Blockchain.

- It can allow the user to construct, sign, and submit new transactions to the JSON-RPC service component of a Diem node.
- It can issue queries to the Diem Blockchain and request the status of a transaction or account.
- Currently, a client can be run on behalf of the end user (for example, for a custodial wallet).

### Consensus

- **Consensus** is a component of a validator.
- The consensus component is responsible for coordination and agreement amongst all validators on the block of transactions to be executed, their order, and the execution results.
- The Diem Blockchain is formed with these agreed-upon transactions and their corresponding execution results.

### Consensus Protocol

- A **consensus protocol** is collectively executed by n validators to accept or reject a transaction and to agree on the ordering of transactions and [execution results](#execution-result).
- See [BFT](#byzantine-fault-tolerance-bft)

### Custodial Wallet

- In a **custodial wallet** model, the wallet service takes custody of customers' funds and private keys.


## D

---

### Designated Dealer

A Designated Dealer is a regulated, well-capitalized financial institution that has the right, pursuant to a contract with Diem Networks, to purchase Diem Coins from, and to sell them to, Diem Networks in minting and burning transactions. Designated Dealers facilitate liquidity in Diem Coins for other DPN participants, such that Diem Coins are readily available to [Regulated VASP](#regulated-vasp) participants and through Regulated VASP participants to end users.


### DiemBFT

- DiemBFT is the Diem protocol's BFT consensus algorithm.
- DiemBFT is based on HotStuff.

### Diem Blockchain

- The **Diem Blockchain** is a ledger of immutable transactions agreed upon by the validators on the Diem network (the network of validators).

### Diem Core

Diem Core is the open source technology on which the Diem Payment Network runs. Diem Core contains software for

* the Diem Blockchain itself, which generates and stores the immutable ledger of confirmed transactions and
* the validation process, which implements the consensus algorithm to validate transactions and add them to the Diem Blockchain immutable ledger.


### Diem Framework
The Diem Framework defines the public API for blockchain updates and the structure of on-chain data. It defines the business logic and access control for the three key pillars of Diem functionality: payments, treasury, and on-chain governance. It is implemented as a set of modules written in the Move programming language and stored on-chain as Move bytecode.


### Diem node
A Diem node is a peer entity of the Diem network that tracks the state of the Diem Blockchain. There are two types of Diem nodes, [validators](#validator) and [FullNodes](#fullnode)).

### Diem Protocol

- **Diem protocol** is the specification of how transactions are submitted, ordered, executed, and recorded within the Diem network.

### DiemAccount.T

- A **`DiemAccount.T`** is a Move resource that holds all the administrative data associated with an account, such as sequence number, balance, and authentication key.
- A **`DiemAccount.T`** is the only resource that every account is guaranteed to contain.

### DiemAccount module

- **The DiemAccount module** is a Move module that contains the code for manipulating the administrative data held in a particular `DiemAccount.T` resource.
- Code for checking or incrementing sequence numbers, withdrawing or depositing currency, and extracting gas deposits is included in the DiemAccount module.

### Diem testnet

- See [testnet](#testnet).


## E

---

### Ed25519

- **Ed25519** is our supported digital signature scheme.
- More specifically, the Diem network uses the PureEdDSA scheme over the Ed25519 curve, as defined in RFC 8032.

### Epoch

- An **epoch** is a period of time during which an instance of the consensus protocol runs with a fixed set of validators and voting rights.
- To change the set of validators and/or their voting rights, the current epoch ends with the commit of a special/administrative smart-contract transaction and a new one is started.

### Event

- An **event** is the user-facing representation of the effects of executing a transaction.
- A transaction may be designed to emit any number of events as a list. For example, a peer-to-peer payment transaction emits a `SentPaymentEvent` for the sender account and a `ReceivedPaymentEvent` for the recipient account.
- In the Diem protocol, events provide evidence that the successful execution of a transaction resulted in a specific effect. The `ReceivedPaymentEvent` (in the above example) allows the recipient to confirm that a payment was received into their account.
- Events are persisted on the blockchain and are used to answer queries by [clients](#client).

### Execution Result

- Execution result of a transaction is a combination of:
  - The new state of the set of accounts affected by the transaction.
  - The events emitted by executing the transaction.
  - The exit code, which indicates either success or a specific error.
  - The number of gas units consumed while executing the transaction.

### Expiration Time

A transaction ceases to be valid after its **expiration time**. If it is assumed that:

- Time_C is the current time that is agreed upon between validators (Time_C is not the local time of the client);
- Time_E is the expiration time of a transaction T_N; and
- Time_C > Time_E and transaction T_N has not been included in the blockchain,

then there is a guarantee that T_N will never be included in the blockchain.

## F

---

### Faucet

- **Faucet** is the way to create Diem currency with no real-world value, only on our testnet.
- The Faucet is a service running along with the testnet. This service only exists to facilitate minting coins for the testnet.
- You can use the Faucet by sending a request to create coins and transfer them into a given account on your behalf.


### FullNode
FullNodes replicate the full state of the blockchain by querying each other or by querying the validators directly.

#### Public FullNodes
These are FullNodes that can be run by anyone who wants to verify the state of the blockchain and synchronize to it.

#### DPN Participant FullNodes
These are FullNodes used by DPN Participants to forward transactions to the validators.



## G

---

### Gas

- **Gas** is a way to pay for computation and storage on a blockchain network. All transactions on the Diem network cost a certain amount of gas.
- The gas required for a transaction depends on the size of the transaction, the computational cost of executing the transaction, and the amount of additional global state created by the transaction (e.g., if new accounts are created).
- The purpose of gas is regulating demand for the limited computational and storage resources of the validators, including preventing denial of service (DoS) attacks.

### Gas Price

- Each transaction specifies the gas price the sender is willing to pay. Gas price is specified in currency/gas units.
- The price of gas required for a transaction depends on the current demand for usage of the network.
- The gas cost is fixed at a point in time. Gas costs are denominated in gas units.

## H

---

### Honest (Validator)

- A validator that faithfully executes the consensus protocol and is not Byzantine.

### HotStuff

- **HotStuff** is a recent proposal for a [BFT](#byzantine-fault-tolerance-bft) consensus protocol.
- DiemBFT, the Diem network's consensus algorithm, is based on HotStuff.
- It simplifies the reasoning about safety, and it addresses some performance limitations of previous consensus protocols.

## L

---

### Leader

- A **leader** is a validator that proposes a block of transactions for the consensus protocol.
- In leader-based protocols, nodes must agree on a leader to make progress.
- Leaders are selected by a function that takes the current [round number](https://fb.quip.com/LkbMAEBIVNbh#ffYACAO6CzD) as input.



## M

---

### Maximum Gas Amount

- The **Maximum Gas Amount** of a transaction is the maximum amount of gas the sender is ready to pay for the transaction.
- The gas charged is equal to the gas price multiplied by units of gas required to process this transaction. If the result is less than the max gas amount, the transaction has been successfully executed.
- If the transaction runs out of gas while it is being executed or the account runs out of balance during execution, then the sender will be charged for gas used and the transaction will fail.

### Mempool

- **Mempool** is one of the components of the validator. It holds an in-memory buffer of transactions that have been submitted but not yet agreed upon and executed. Mempool receives transactions from [JSON-RPC Service](#json-rpc-service).
- Transactions in the mempool of a validator are added from the JSON-RPC Service of the current node and from the mempool of other Diem nodes.
- When the current validator is the leader, its consensus component pulls the transactions from its mempool and proposes the order of the transactions that form a block. The validator quorum then votes on the proposal.

### Merkle Trees

- **Merkle tree** is a type of authenticated data structure that allows for efficient verification of data integrity and updates.
- The Diem network treats the entire blockchain as a single data structure that records the history of transactions and states over time.
- The Merkle tree implementation simplifies the work of apps accessing the blockchain. It allows apps to:
  - Read any data from any point in time.
  - Verify the integrity of the data using a unified framework.

### Merkle Accumulator

- The [Merkle Accumulator](https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf) is an _append-only_ Merkle tree that the Diem Blockchain uses to store the ledger.
- Merkle accumulators can provide proofs that a transaction was included in the chain (“proof of inclusion”).
- They are also called ["history trees"](http://people.cs.vt.edu/danfeng/courses/cs6204/sp10-papers/crosby.pdf) in literature.

### Move

- **Move** is a new programming language that implements all the transactions on the Diem Blockchain.
- It has two different kinds of code &mdash; [transaction scripts](#transaction-script) and [Move modules](#move-module).
- For further information on Move, refer to the [Move technical paper](/docs/technical-papers/move-paper)

### Move Bytecode

- Move programs are compiled into Move bytecode.
- Move bytecode is used to express transaction scripts and Move modules.

### Move Module

- A **Move module** defines the rules for updating the global state of the Diem Blockchain.
- In the Diem protocol, a Move module is a **smart contract**.
- Each user-submitted transaction includes a transaction script. The transaction script invokes procedures of one or more Move modules to update the global state of the blockchain according to the rules.

### Move Resources

- **Move resources** contain data that can be accessed according to the **procedures** declared in a Move **module.**
- Move resources can never be copied, reused, or lost. This protects Move programmers from accidentally or intentionally losing track of a resource.

### Move Virtual Machine (MVM)

- The **Move virtual machine** executes transaction scripts written in [Move bytecode](#move-bytecode) to produce an [execution result](#execution-result). This result is used to update the blockchain **state**.
- The virtual machine is part of a [validator](#validator).

## N

---

### Node

- A **node** is a peer entity of the Diem network that tracks the state of the Diem Blockchain.
- A Diem node consists of logical components. [Mempool](#mempool), [consensus](#consensus), and the [virtual machine](#virtual-machine) are examples of node components.

## O

---

### Open-Source Community

- **Open-source community** is a term used for a group of developers who work on open-source software. If you're reading this glossary, then you are part of the Diem project's developer community.

## P

---

### Proof

- A **proof** is a way to verify the accuracy of data in the blockchain.
- Every operation in the Diem Blockchain can be verified cryptographically that it is indeed correct and that data has not been omitted.
- For example, if a user queries the information within a particular executed transaction, they will be provided with a cryptographic proof that the data returned to them is correct.

## R

---

### Regulated VASP

A Regulated VASP is a VASP that is registered or licensed in a Financial Action Task Force ("FATF") member jurisdiction and permitted to perform VASP activities under such license or registration. A Regulated VASP must be authorized by Diem Networks to operate as a VASP participant on the Diem Payment Network.

Under the DPN Rules, a VASP is defined as a natural or legal person that as a business conducts one or more of the following activities or operations for or on behalf of another natural or legal person:
- Exchanges between Diem Coins and fiat currencies;
- Exchanges between Diem Coins and other virtual assets;
- Transfers of Diem Coins;
- Engages in safekeeping or administration of Diem Coins; and
- Otherwise provides financial services related to Diem Coins.


### Round

- A **round** consists of achieving consensus on a block of transactions and their execution results.

### Round Number

- A **round number** is a shared counter used to select leaders during an [epoch](#epoch) of the consensus protocol.

## S

---

### Sequence Number

- The **sequence number** for an account indicates the number of transactions that have been submitted and committed on chain from that account. It is incremented every time a transaction sent from that account is executed or aborted and stored in the blockchain.
- A transaction is executed only if it matches the current sequence number for the sender account. This helps sequence multiple transactions from the same sender and prevents replay attacks.
- If the current sequence number of an account A is X, then a transaction T on account A will only be executed if T's sequence number is X.
- These transactions will be held in mempool until they are the next sequence number for that account (or until they expire).
- When the transaction is applied, the sequence number of the account will become X+1. The account has a strictly increasing sequence number.

### Sender

- _Alternate name_: Sender address.
- **Sender** is the address of the originator account for a transaction. A transaction must be signed by the originator.

### Smart Contract

- See [Move Module](#move-module).

### State

- A **state** in the Diem protocol is a snapshot of the distributed database.
- A transaction modifies the database and produces a new and updated state.

### State Root Hash

- **State root hash** is a [Merkle hash](https://en.wikipedia.org/wiki/Merkle_tree) over all keys and values the state of the Diem Blockchain at a given version.

## T

---

### testnet

- The **testnet** is a publicly deployed instance of the Diem network that runs using a set of validator test nodes.
- The testnet is a demonstration of the Diem network that is built for experimenting with new ideas
- The testnet simulates a digital payment system and the coins on the testnet have _no real world value_.

### Transaction

- A raw **transaction** contains the following fields:
  - [Sender (account address)](#account-address)
  - [Transaction script](#transaction-script)
  - [Gas price](#gas-price)
  - [Maximum gas amount](#maximum-gas-amount)
  - [Sequence number](#sequence-number)
  - [Expiration time](#expiration-time)
- A signed transaction is a raw transaction with the digital signature.
- An executed transaction changes the state of the Diem Blockchain.

### Transaction Script

- Each transaction submitted by a user includes a **transaction script**.
- It represents the operation a client submits to a validator.
- The operation could be a request to move coins from user A to user B, or it could involve interactions with published [Move modules](#move-modules)/smart contracts.
- The transaction script is an arbitrary program that interacts with resources published in the global storage of the Diem Blockchain by calling the procedures of a module. It encodes the logic for a transaction.
- A single transaction script can send funds to multiple recipients and invoke procedures from several different modules.
- A transaction script **is not** stored in the global state and cannot be invoked by other transaction scripts. It is a single-use program.

## V

---

### Validator

- _Alternate name_: Validators.
- A **validator** is an entity of the Diem ecosystem that validates on the Diem Blockchain. It receives requests from clients and runs consensus, execution, and storage.
- A validator maintains the history of all the transactions on the blockchain.
- Internally, a validator needs to keep the current state, to execute transactions, and to calculate the next state.

### Version

- A **version** is also called “height” in blockchain literature.
- The Diem Blockchain doesn't have an explicit notion of a block &mdash; it only uses blocks for batching and executing transactions.
- A transaction at height 0 is the first transaction (genesis transaction), and a transaction at height 100 is the 101st transaction in the transaction store.

## W

---

### Well-Formed Transaction

A Diem transaction is **well formed** if each of the following conditions are true for the transaction:

- The transaction has a valid signature.
- An account exists at the sender address.
- It includes a public key, and the hash of the public key matches the sender account's authentication key.
- The sequence number of the transaction matches the sender account's sequence number.
- The sender account's balance is greater than the [maximum gas amount](#maximum-gas-amount).
- The expiration time of the transaction has not passed.
