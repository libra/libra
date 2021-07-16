---
id: diem-protocol
title: 'Basic Concepts & Terms'
sidebar_label: Diem Protocol
---

The Diem Blockchain (referred to as blockchain in the rest of this page) is a cryptographically authenticated distributed database. This document briefly describes the key concepts of the  blockchain. For a detailed description of all the elements of the  blockchain, refer to the [Diem Blockchain technical paper](/docs/technical-papers/the-diem-blockchain-paper).

The Diem Blockchain is operated by a distributed network of [validator nodes](#validator-node-validators), also known as validators. The validators collectively follow a [consensus protocol](/reference/glossary.md#consensus) to agree on the ordering and execution of transactions on the blockchain.

The Diem testnet is an early prototype of the Diem Blockchain protocol, also known as Diem Core.


## Transactions and states

At the heart of the Diem protocol are two fundamental concepts — transactions and states. At any point in time, the blockchain has a “ledger state.” The ledger state (or state for short) represents the current snapshot of data on the chain. Executing a transaction changes the state of the Diem Blockchain.




![Figure 1.0 A Transaction changes state.](/img/docs/transactions.svg)
<small className="figure">FIGURE 1.0 TRANSACTIONS CHANGE STATE</small>

Figure 1.0 represents the change of state of the Diem Blockchain that occurs when a transaction is executed. In this figure:

| Name | Description |
| ---- | ----------- |
| Accounts **A** and **B** | Represent Alice's and Bob's accounts on the Diem Blockchain |
| S<sub>N-1</sub> | Represents the (N-1)th state of the blockchain. In this state, Alice's account has a balance of 110 Diem Coins, and Bob's account has a balance of 52 Diem Coins. |
| T<sub>N</sub> | This is the n-th transaction executed on the blockchain. In this example, it represents Alice sending 10 Diem Coins to Bob. |
| **F** | It is a deterministic function. F always returns the same final state for a specific initial state and a specific transaction. If the current state of the blockchain is S<sub>N-1</sub>, and transaction T<sub>N</sub> is executed on state S<sub>N-1</sub>, the new state of the blockchain is always S<sub>N</sub>. |
| **S<sub>N</sub>** | is the n-th state of the blockchain. When the transaction T<sub>N</sub> is applied to the blockchain, it generates the new state S<sub>N</sub> (an outcome of applying F to S<sub>N-1</sub> and T<sub>N</sub>). This causes Alice’s balance to be reduced by 10 to 100 Diem Coins and Bob’s balance to be increased by 10 to 62 Diem Coins. The new state S<sub>N</sub> now shows these updated balances. |


The Diem Blockchain uses the [Move language](/move/overview.md) to implement the deterministic execution function F.

### Transactions

Clients of the Diem Blockchain submit transactions to request updates to the ledger state. A signed transaction on the blockchain contains:

- **Sender address** — Account address of the sender of the transaction.
- **Sender public key** — The public key that corresponds to the private key used to sign the transaction.
- **Program** — The program is comprised of the following:
  - A Move bytecode transaction script.
  - An optional list of inputs to the script. For a peer-to-peer transaction, the inputs contain the information about the recipient and the amount transferred to the recipient.
  - An optional list of Move bytecode modules to publish.
- **Gas price** (in specified currency/gas units) — The amount the sender is willing to pay per unit of [gas](reference/glossary.md#gas) to execute the transaction. Gas is a way to pay for computation and storage. A gas unit is an abstract measurement of computation with no inherent real-world value.
- **Maximum gas amount** — The maximum units of gas the transaction is allowed to consume.
- **Gas currency code** - The currency code used to pay for gas
- **Sequence number** — An unsigned integer that must be equal to the sequence number stored under the sender’s account at the time of execution.
- **Expiration time** — The time after which the transaction ceases to be valid.
- **Signature** — The digital signature that verifies that the sender signed the transaction.

The transaction script is an arbitrary program that encodes the logic of a transaction and interacts with resources published in the distributed database of the Diem Blockchain.

### Ledger state

The ledger state or global state of the Diem Blockchain comprises the state of all accounts in the blockchain. To execute transactions, each validator must know the global state of the latest version of the blockchain's distributed database. See [versioned database](#versioned-database).

## Versioned database

All of the data in the Diem Blockchain is persisted in a single-versioned distributed database. A version number is an unsigned 64-bit integer that corresponds to the number of transactions the system has executed.

The versioned database allows validators to:

- Execute a transaction against the ledger state at the latest version.
- Respond to client queries about ledger history at both current and previous versions.

## Account

A [Diem account](accounts.md) is a container for Move modules and Move resources. It is identified by an account address. This essentially means that the state of each account is comprised of both code and data:

- **Move modules** contain code (type and procedure declarations), but they do not contain data. The procedures of a module encode the rules for updating the global state of the blockchain.
- **Move resources** contain data but no code. Every resource value has a type that is declared in a module published in the distributed database of the blockchain.

An account may contain an arbitrary number of Move resources and Move modules.

### Account address

The address of a Diem account is a 16-byte value. The [account address](reference/glossary.md#account-address) is derived from a cryptographic hash of a user’s public verification key concatenated with a signature scheme identifier byte. The Diem Blockchain supports two signature schemes: Ed25519 and MultiEd25519 (for multi-signature transactions). To sign a transaction the client must use the private key corresponding to that account.



## Proof

All of the data in the Diem Blockchain is stored in a single-versioned distributed database. The storage is used to persist agreed upon blocks of transactions and their execution results. The blockchain is represented as an ever-growing [Merkle tree of transactions](reference/glossary.md#merkle-trees). A “leaf” is appended to the tree for each transaction executed on the blockchain.


- A proof is a way to verify the truth of data in the Diem Blockchain.
- Every operation stored on the blockchain can be verified cryptographically, and the resultant proof also proves that validators all agreed on the state at that time. For example, if the client queried the latest _n_ transactions from an account, the proof verifies that no transactions are added, omitted, or modified from the query response.

In a blockchain, the client does not need to trust the entity from which it is receiving data. A client could query for the state of an account, ask whether a specific transaction was processed, and so on. As with other Merkle trees, the ledger history can provide an $O(\log n)$-sized proof of a specific transaction object, where n is the total number of transactions processed.

## Validator node (validator)

Clients of the Diem Blockchain create transactions and submit them to a validator node or validator. A validator runs a consensus protocol (together with other validators), executes the transactions, and stores the transactions and the execution results on the blockchain. Validators decide which transactions will be added to the blockchain and in which order.
![Figure 1.1 Logical components of a validator](/img/docs/validator.svg)
<small className="figure">FIGURE 1.1 LOGICAL COMPONENTS OF A VALIDATOR</small>

A validator contains the following logical components:

#### JSON-RPC Service

The JSON-RPC Service is the external interface of the validator. When a client makes a request to the Diem node, it goes to the JSON-RPC Service first.

#### Mempool

- Mempool is a buffer replicated between validators that holds the transactions “waiting” to be executed.
- Mempool performs initial checks on the requests to protect the other parts of the validator from corrupt or high volume input.
- When a new transaction passes the initial checks and is added to a validator's mempool, it will be shared to the mempools of other validators in the network.


#### Consensus

The consensus component is responsible for ordering blocks of transactions and agreeing on the results of execution by participating in the [consensus protocol](reference/glossary.md#consensus) with other validators in the network.

#### Execution

- The execution component utilizes the virtual machine (VM) to execute transactions.
- This component's job is to coordinate the execution of a block of transactions and maintain a transient state that can be voted upon by consensus.
- Execution maintains an in-memory representation of the results of execution until consensus commits the block to the distributed database.

#### Virtual Machine (VM)

- Mempool uses the VM component to perform validation checks on transactions.
- VM is used to run the program included in a transaction and determine the results.

#### Storage

The storage component is used to persist agreed upon blocks of transactions and their execution results.

For information on interactions of each validator component with other components, refer to [Life of a Transaction](life-of-a-transaction.md).


## Byzantine Fault Tolerance (BFT) consensus approach

The Diem payment system uses a BFT [consensus protocol](reference/glossary.md#consensus-protocol) to form agreement among [validators](reference/glossary.md#validator-node) on the ledger of finalized transactions and their execution. The DiemBFT [consensus protocol](reference/glossary.md#consensus-protocol) provides fault tolerance of up to one-third of malicious validators.

Each validator maintains the history of all the transactions on the blockchain. Internally, a validator needs to keep the current state to execute transactions and to calculate the next state. You can learn more about the logical components of a validator in [Life of a Transaction](life-of-a-transaction.md).

In addition to validators, the Diem network will have FullNodes that verify the history of the chain. The [FullNodes](nodes.md#fullnodes) can serve queries about the blockchain state. They additionally constitute an external validation resource of the history of finalized transactions and their execution. They receive transactions from upstream nodes and then re-execute them locally (the same way a validator executes transactions). FullNodes store results of re-execution to local storage. In doing so, FullNodes will notice and can provide evidence if there is any attempt to rewrite history. This helps ensure that the validators are not colluding on arbitrary transaction execution.


###### tags: `core`
