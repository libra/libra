---
id: move-introduction
title: Move Introduction
sidebar_label: Introduction
---

import MoveArchitecture from 'img/docs/move-architecture.svg';

Welcome to Move, a next generation language for secure, sandboxed, and formally verified programming. Its first use case is for the Diem blockchain, where Move provides the foundation for its implementation. Move allows developers to write programs that flexibly manage and transfer assets, while providing the security and protections against attacks on those assets. However, Move has been developed with use cases in mind outside a blockchain context as well.

Move takes its cue from [Rust](https://www.rust-lang.org/) by using resource types with move (hence the name) semantics as an explicit representation of digital assets, such as currency.

![Figure 1.1 Move Methods](/img/docs/move-methods.svg)
<small className="figure">Figure 1.1 Move Methods</small>

## Who is Move for?

Move was designed and created as a secure, verified, yet flexible programming language. The first use of Move is for the implementation of the Diem blockchain. That said, the language is still evolving. Move has the potential to be a language for other blockchains, and even non-blockchain use cases as well.

Given custom Move modules will not be supported at the [launch](https://diem.com/white-paper/#whats-next) of the Diem Payment Network (DPN), we are targeting an early Move Developer persona.

The early Move Developer is one with some programming experience, who wants to begin understanding the core programming language and see examples of its usage.

### Hobbyists

Understanding that the capability to create custom modules on the Diem Payment Network will not be available at launch, the hobbyist Move Developer is interested in learning the intricacies of the language. She will understand the basic syntax, the standard libraries available, and write example code that can be executed using the Move CLI. The Move Developer may even want to dig into understanding how the Move Virtual Machine executes the code she writes.

### Core Contributor

Beyond a hobbyist wanting to stay ahead of the curve for the core programming language is someone who may want to [contribute](https://diem.com/en-US/cla-sign/) directly to Move. Whether this includes submitting language improvements or even, in the future, adding core modules available on the Diem Payment Network, the core contributor will understand Move at a deep level. Once familiar with Move, the core contributor may want to submit a request to the Diem Association to add new transaction or module types, via the [Diem Improvement Protocol (DIP) process](https://dip.diem.com/).

### Who Move is currently not targeting

Currently, Move is not targeting developers who wish to create custom modules and contracts for use on the Diem Payment Network. We are also not targeting novice developers who expect a completely polished developer experience even in testing the language.

## Move Architecture

Move has all of the syntax and semantics you would expect from a first-class programming language. However, there is an entire architecture dedicated to creating, using, and executing code based on Move. The diagram below shows the architecture of Move as it pertains to the Diem Payment Network, from using the source language to script execution. Click on a specific topic of the diagram to be taken to more information about that specific area.

<MoveArchitecture alt="Figure 1.2 Move Architecture" />
<small className="figure">Figure 1.2 Move Architecture</small>

## Where Do I Start?

Begin with understanding [modules and scripts](./modules-and-scripts.md) and then work through the [first tutorial on creating coins](./creating-coins.md). And then use the sidebar to walkthrough even more details about the language.
