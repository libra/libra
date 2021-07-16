const {category, categoryBoilerplate, getReference} = require('./components');

const Sidebar = [
  ...categoryBoilerplate('wallet-app/overview', 'wallet-app'),
  category('Guides', [
    'wallet-app/wallet-guide',
  ]),
  category('Diem Reference Wallet', [
    category('Basics', [
      'wallet-app/intro-to-drw',
    ]),
    category('Getting Started', [
      'wallet-app/develop-reference-wallet',
    ]),
    category('Test', [
      'wallet-app/public-demo-wallet',
      'wallet-app/try-local-web-wallet',
      'wallet-app/try-local-mobile-wallet',
      'wallet-app/try-wallet-admin',
    ]),
  ]),
  ...getReference(),
];

module.exports = Sidebar;
