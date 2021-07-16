---
id: gas
title:  Gas
sidebar_label:  Gas
---



Gas is a way for the Move virtual machine to track and account for the abstract representation of computational resources consumed during execution. In other words, gas is used to track and measure the network resources used during a transaction in the Diem Payment Network (DPN).

[Gas](/reference/glossary.md#gas) is used to ensure that all Move programs running on the Diem Blockchain terminate, so that the computational resources used are bounded. It also provides the ability to charge a transaction fee, partly based on consumed resources during a transaction.

### Using gas to specify a transaction fee

When a client submits a transaction for execution to the Diem Blockchain, it contains a specified:

* `max_gas_amount`: This is the maximum amount of gas units that can be used to execute a transaction, and therefore bounds the amount of computational resources that can be consumed by a transaction.
* `gas_price`: This is a way to move from the abstract units of resource consumption that are used in the virtual machine (VM) — gas units — into a transaction fee in the specified gas currency.
* `gas_currency`: This is the currency of the transaction fee (which is at most `gas_price * max_gas_amount`) charged to the client.



## Core design principles

Designing gas in Move has been motivated by three central principles:

* Move is Turing complete. Because of this, determining if a given Move program terminates cannot be decided statically. However, by ensuring that (1) every bytecode instruction has a non-zero gas consumption, and (2) the amount of gas that any program can be started with is bounded, we get this termination property for programs almost free of cost.
* We want to both discourage DDoS attacks and encourage judicious use of the DPN. The gas usage for a transaction is correlated with the resource consumption (e.g., time taken to execute) of the transaction and the gas price--and hence the transaction fee, should rise-and-fall with contention in the DPN. At launch, we expect **gas prices to be at or near zero**; but in periods of high contention, the gas price can be used to prioritize transactions, which will encourage sending only needed transactions during such times.
* The resource usage of a program needs to be agreed upon in consensus. This means that the method of accounting for resource consumption needs to be deterministic. This rules out other means of tracking resource usage, such as cycle counters or any type of timing-based methods as they are not guaranteed to be deterministic across nodes. The method for tracking resource usage needs to be abstract.



## Technical overview

In this section, we'll provide a high-level technical overview of gas in the virtual machine (VM).

### Different types of resources

For the VM to execute a transaction, the gas system needs to track the primary resources that are used by both the DPN and the VM. These fall into three resource "dimensions":

1. The computational cost of executing the transaction.
2. The network cost of sending the transaction over the DPN.
3. The cost (storage) of storing the data created and read during the transaction on the Diem Blockchain. The first two of these resources (compute and network) are ephemeral. On the other hand, storage is long lived. Once data is allocated, that data persists until it is deleted. In the case of accounts, the data lives indefinitely.

Each of these resource dimensions can fluctuate independently of the other. However, we also have only one gas price. This means that the gas usage contributed for each resource dimension needs to be correct, because the gas price only acts as a multiplier to the total gas usage, not usage by dimension. The essential property that we design for is that gas usage of a transaction needs to be as highly correlated as possible with the real-world cost associated with executing a transaction.

### Transaction prioritization, gas, and currencies

When a transaction is sent, that transaction is prioritized based on a number of different criteria. One of these is the normalized gas price for the transaction. Specifically, for transactions that are subject to ordering by gas price (i.e., non-governance transactions) these prices are first normalized to Diem Coins based upon the current gas currency to Diem Coin conversion rate that is stored on-chain. Transactions are then ranked (in part) based upon this normalized gas price.

For example:

* Bob sends a transaction with `gas_price` 10 and `gas_currency` of “BobCoins”.
* Alice sends a transaction at the same time with `gas_price` 20 and `gas_currency` of “AliceCoins”.

If the on-chain “BobCoins” to Diem Coins exchange rate is 2.1 and the on-chain “AliceCoins” to Diem Coins exchange rate is 1,
* Bob’s transaction has a normalized gas price of `10 * 2.1 = 21`.
* Alice’s transaction has a normalized gas price of `20 * 1 = 20`.

Then, Bob’s transaction would be ranked higher than Alice’s.

### Gas and transaction flow
The VM is responsible for computing the resource usage of a transaction. The transaction contains information on the gas price and the gas currency. The VM’s computed resource usage is then multiplied by this gas price to arrive at the fee (in the specified gas currency) for execution.

Different aspects of resource usage are charged for at different times in the transaction flow. The basics of the transaction flow and the gas-related logic are detailed in the following diagram:
![Figure 1.0 Gas and Transaction Flow](/img/docs/using-gas.svg)
<small className="figure">FIGURE 1.0 Gas and Transaction Flow</small>

In the diagram, both the prologue and epilogue sections are marked in red. This is because both of these sections of the transaction flow need to be **unmetered**:
* In the prologue, it's not known if the submitting account has sufficient funds to cover its gas liability, or if the transaction submitter even has authority over the submitting account. Due to this lack of knowledge, when the prologue is executed, it needs to be unmetered. Deducting gas for transactions that fail the prologue could allow unauthorized deductions from accounts.
* The epilogue is in part responsible for debiting the execution fee from the sending account and distributing it. Because of this, the epilogue must run even if the transaction execution has run out of gas. Likewise, we don't want it to run out of gas while debiting the transaction sender's account as this would cause additional computation to be performed without any transaction fee being charged.

Taken together, this non-metering of both the prologue and epilogue requires the MIN_TXN_FEE to be enough to cover the average cost of running both.

After the prologue has run, and we've checked in part that the account can cover its gas liability, the rest of the transaction flow starts with the "gas tank" full at `max_gas_amount`. The `MIN_TXN_FEE` is charged, after which the gas tank is then deducted (or "charged") for each instruction executed by the VM. This per-instruction deduction continues until either:
* The execution of the transaction has completed, after which a charge for global writes to memory is charged, and the epilogue is run and the execution fee deducted, or
* The "gas tank" becomes empty, in which case an `OutOfGas` error is raised.

In the former, the fee is collected and the result of the transaction is persisted. The latter causes the execution of the transaction to stop when the error is raised, following which the total gas liability of the transaction is collected. No other remnants of the execution are committed other than the deduction in this case.


###### tags: `core`
