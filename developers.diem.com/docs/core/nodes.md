---
id: nodes
title: Diem Nodes
---


A Diem node is a peer entity of the Diem ecosystem that tracks the state of the Diem Blockchain. Clients interact with the blockchain via Diem nodes. There are two types of nodes:

* [Validator Nodes (Validators)](#validator-nodes-validators)
* [FullNodes](#fullnodes)

Each Diem node comprises several logical components:
* JSON-RPC service
* Mempool
* Storage
* Consensus (only validators)
* Execution
* State synchronizer
* Virtual machine

The Diem Core software can be configured to run as a validator node or as a FullNode; the primary distinction between the two is that consensus is disabled in FullNodes.


## Validator Nodes (validators)

Validator nodes use a distributed consensus protocol to validate the transactions submitted by a Diem client. They process these transactions to include them in the Diem Blockchain’s database, which validators maintain. This means that these nodes always have the current state of the blockchain.

A validator node is characterized by the following:
* It participates in consensus.
* The JSON-RPC Service component is disabled.
* It communicates directly with other validators over a hidden network.
* It may be configured to store either all the historical data or part of the historical data from the Diem Blockchain.
* It uses its State Synchronizer component to “catch up” to the latest state of the blockchain.

Learn more about how validator components process and execute transactions on the Diem Blockchain [here](life-of-a-transaction.md).


## FullNodes

FullNodes can be run by anyone who wants to verify the state of the Diem Blockchain and synchronize to it. FullNodes replicate the full state of the blockchain by querying each other or by querying the validators directly.  FullNodes can also accept transactions submitted by Diem clients and forward them to validators.

### Public FullNodes
A public FullNode is characterized by the following:
* It uses the same software as the validator.
* Consensus is disabled.
* It connects directly to one or more validators to submit transactions and synchronize to the state of the Diem Blockchain.

Third-party blockchain explorers, wallets, exchanges, and DApps may run a local FullNode to:
* Leverage the JSON-RPC protocol for richer blockchain interactions.
* Get a consistent view of the Diem Payment Network.
* Avoid rate limitations on read traffic.
* Run custom analytics on historical data.
* Get notifications about particular on-chain events.

Check out how you can configure and run your own public FullNode [here](/node/config-deploy-fn.md).


## Node networks
Depending on their configuration, nodes can form different peer-to-peer state synchronization networks. Each Diem node can participate in multiple networks as shown in the figure below.
* Validator network
* Public FullNode network

![img](/img/docs/v-fn-network.svg)

### Two-tier architecture
Validators and public FullNodes form a two-tiered architecture. A public FullNode network is not peer-to-peer, and it receives updates on new blocks only from the validator it is connected to.


### Separate network stacks
The Diem Payment Network has separate network stacks for the different types of Diem nodes. The advantages of having separate network stacks include:
* Clean separation between the different networks.
* Better support for security preferences (bidirectional vs server authentication).
* Allowance for isolated discovery protocols (on-chain discovery for validator’s public endpoint vs manual configuration for private organizations).


## Node synchronization
A Diem node synchronizes to the latest state of the Diem Blockchain when:
* It comes online for the first time (bootstrap).
* It restarts.
* It comes online after being offline for some time.
* When there is a network partition.
* FullNodes synchronize with their upstream nodes continuously during a normal workload.

### State synchronizer
Each Diem node contains a State Synchronizer (SS) component which is used to synchronize the state of a node to its upstream peers. This component has the same function for all types of Diem nodes. It utilizes the dedicated peer-to-peer network stack to perform synchronization and it uses a long-polling API.

The upstream peers that are used for synchronizing to the latest state of the blockchain are different for each type of node:
* Validators use the validator network.
* Public FullNodes can either use the initial set of peers or the validators that are open for public access.

### Synchronization API
The State Synchronizer of a Diem node communicates with the State Synchronizer of upstream nodes to get chunks of transactions to synchronize with the current state of the Diem Blockchain. Learn more about how this works in the specifications [here](https://github.com/diem/diem/tree/main/specifications/state_sync).


###### tags: `core`, `node`
