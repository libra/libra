---
id: welcome-to-diem
disable_pagination: true
sidebar_label: Home
title: Welcome to Diem
hide_title: true
---

<h1 className="p">Welcome Diem Developers. <br />
Explore the technical and economic concepts behind the Diem Payment Network, experiment with specialized tutorials, or start building with the Development Tools.</h1>

<NotificationBar>
  <p>
    During the first phase of our rollout, only a limited number of approved organizations will be participating on the network. To stay informed of updates, please sign up <a href="/newsletter_form">here</a> to be notified.
  </p>
</NotificationBar>

<MarketingModule
  copy="Explore the official Diem Reference Wallet, with full functionality and interactive testnet connectivity"
  cta="Try the Wallet"
  ctaLink="/reference-wallet"
  img="/img/marketing-module.jpg"
/>

### Topics

<CardsWrapper>
  <OverlayCard
    description="Protocol Overview, Transaction Types, Nodes, Accounts"
    icon="img/core-contributors.svg"
    iconDark="img/core-contributors-dark.svg"
    title="Core Concepts"
    to="/docs/core/overview"
  />
  <OverlayCard
    description="Requirements, Configuration, Running a Local Network"
    icon="img/node-operators.svg"
    iconDark="img/node-operators-dark.svg"
    title="Nodes"
    to="/docs/node/overview"
  />
  <OverlayCard
    description="Integration, Reference Wallet"
    icon="img/wallet-app.svg"
    iconDark="img/wallet-app-dark.svg"
    title="Wallets"
    to="/docs/wallet-app/overview"
  />
  <OverlayCard
    description="Integration, Reference Merchant"
    icon="img/docs/merchant-solutions.svg"
    iconDark="img/docs/merchant-solutions-dark.svg"
    title="Merchants"
    to="/docs/merchant/overview"
  />
  <OverlayCard
    description="Key Components, Writing Modules, Testing & Debugging"
    icon="img/move.svg"
    iconDark="img/move-dark.svg"
    title="Move"
    to="/docs/move/overview"
  />
</CardsWrapper>

### Tools

<CardsWrapper cardsPerRow={4}>
  <SimpleTextCard
    icon="img/document.svg"
    iconDark="img/document-dark.svg"
    title="SDKs"
    to="/docs/sdks/overview"
  />
  <SimpleTextCard
    icon="img/core-contributors.svg"
    iconDark="img/core-contributors-dark.svg"
    title="CLI"
    to="/docs/cli"
  />
  <SimpleTextCard
    icon="img/github.svg"
    iconDark="img/github-dark.svg"
    title="GitHub"
    to="https://github.com/diem/diem"
  />
</CardsWrapper>
