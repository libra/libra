import React from 'react';

import SimpleTextCard from '../Cards/SimpleTextCard';

const CoreReference = () => (
  <SimpleTextCard
    icon="img/core-contributors.svg"
    iconDark="img/core-contributors-dark.svg"
    smallerImage
    title="Core contributor overview"
    to="/docs/core/overview"
  />
);

const MerchantReference = () => (
  <SimpleTextCard
    icon="img/docs/merchant-solutions.svg"
    iconDark="img/docs/merchant-solutions-dark.svg"
    smallerImage
    title="Merchant solutions overview"
    to="/docs/merchant/overview"
  />
);

const WalletReference = () => (
  <SimpleTextCard
    icon="img/wallet-app.svg"
    iconDark="img/wallet-app-dark.svg"
    smallerImage
    title="Wallet developer overview"
    to="/docs/wallet-app/overview"
  />
);

const MoveReference = () => (
  <SimpleTextCard
    icon="img/move.svg"
    iconDark="img/move-dark.svg"
    smallerImage
    title="Move overview"
    to="/docs/move/overview"
  />
);

const NodeReference = () => (
  <SimpleTextCard
    icon="img/node-operators.svg"
    iconDark="img/node-operators-dark.svg"
    smallerImage
    title="Node overview"
    to="/docs/node/overview"
  />
);

export default {
  CoreReference,
  MerchantReference,
  WalletReference,
  MoveReference,
  NodeReference,
};
