---
id: the-diem-blockchain-paper
title: The Diem Blockchain
---

***Note to readers: On December 1, 2020, the Libra Association was renamed to Diem Association. This report was published before the Association released White Paper v2.0 in April 2020, which included a number of key updates to the Libra payment system. Outdated links have been removed, but otherwise, this report has not been modified to incorporate the updates and should be read in that context. Features of the project as implemented may differ based on regulatory approvals or other considerations, and may evolve over time.***

## Abstract

The Diem Blockchain is a decentralized, programmable database designed to support a low-volatility cryptocurrency that will have the ability to serve as an efficient medium of exchange for billions of people around the world. We present a proposal for the Diem protocol, which implements the Diem Blockchain and aims to create a financial infrastructure that can foster innovation, lower barriers to entry, and improve access to financial services. To validate the design of the Diem protocol, we have built an open-source prototype implementation — _Diem Core_ — in anticipation of a global collaborative effort to advance this new ecosystem.

The Diem protocol allows a set of replicas — referred to as validators — from different authorities to jointly maintain a database of programmable resources. These resources are owned by different user accounts authenticated by public key cryptography and adhere to custom rules specified by the developers of these resources. Validators process transactions and interact with each other to reach consensus on the state of the database. Transactions are based on predefined and, in future versions, user-defined smart contracts in a new programming language called _Move_.

We use Move to define the core mechanisms of the blockchain, such as the currency and validator membership. These core mechanisms enable the creation of a unique governance mechanism that builds on the stability and reputation of existing institutions in the early days but transitions to a fully open system over time.

### Downloads

<p>
  <a href="/papers/the-diem-blockchain/2020-05-26.pdf" target="_blank">
    <img className="deep-dive-image" src="/img/docs/diem-blockchain-pdf.png" alt="The Diem Blockchain PDF Download" />
  </a>
</p>
<a href="/papers">Previous versions</a>
