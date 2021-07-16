---
id: state-machine-replication-paper
title: State Machine Replication
---

***Note to readers: On December 1, 2020, the Libra Association was renamed to Diem Association. This report was modified in April 2020 to incorporate updates to the Libra payment system as found in the White Paper v2.0. Features of the project as implemented may differ based on regulatory approvals or other considerations, and may evolve over time.***

## Abstract

This report describes the Diem Byzantine Fault Tolerance (DiemBFT) algorithmic core and discusses next steps in its production. The consensus protocol is responsible for forming agreement on ordering and finalizing transactions among a configurable set of validators. DiemBFT maintains safety against network asynchrony and even if at any particular configuration epoch, a threshold of the participants are Byzantine.

DiemBFT is based on HotStuff, a recent protocol that leverages several decades of scientific advances in Byzantine Fault Tolerance (BFT) and achieves the strong scalability and security properties required by internet settings. Several novel features distinguish DiemBFT from HotStuff. DiemBFT incorporates a novel round synchronization mechanism that provides bounded commit latency under synchrony. It introduces a nil-block vote that allows proposals to commit despite having faulty leaders. It encapsulates the correct behavior by participants in a “tcb”-able module, allowing it to run within a secure hardware enclave that reduces the attack surface on participants.

DiemBFT can reconfigure itself, by embedding configuration-change commands in the sequence. A new configuration epoch may change everything from the validator set to the protocol itself.

### Downloads

<p>
  <a href="/papers/diem-consensus-state-machine-replication-in-the-diem-blockchain/2020-05-26.pdf" target="_blank">
    <img className="deep-dive-image" src="/img/docs/state-machine-pdf.png" alt="State Machine Replication in the Diem Blockchain PDF Download" />
  </a>
</p>

<a href="/papers">Previous versions</a>
