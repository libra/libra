const {category, categoryBoilerplate, getReference} = require('./components');

const Sidebar = [
  ...categoryBoilerplate('tutorials/overview', { url: 'cog', type: 'png' }),
  category('Basics', [
    'tutorials/my-first-transaction',
    'tutorials/my-first-client',
    'tutorials/query-the-blockchain',
    'tutorials/run-local-network',
  ]),
  category('Diem Reference Wallet', [
    'tutorials/public-demo-wallet',
    'tutorials/try-local-web-wallet',
    'tutorials/try-wallet-admin',
  ]),
  category('Diem Reference Merchant', [
    'tutorials/try-demo-merchant',
    'tutorials/local-merchant-store',
    'tutorials/payment-mgmt',
  ]),
  ...getReference(),
];

module.exports = Sidebar;
