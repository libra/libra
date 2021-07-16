const {category, categoryBoilerplate, getReference} = require('./components');

const Sidebar = [
  ...categoryBoilerplate('core/overview', 'core-contributors'),
  category('Basics', [
    'core/diem-protocol',
    'core/nodes',
    'core/accounts',
    'core/gas',
    'core/events',
  ]),
  category('Transactions', [
    'core/transaction-types',
    'core/life-of-a-transaction',
    'core/my-first-transaction',
    'core/clients',
  ]),
  category('Reference', [
    {
      type: 'link',
      href: 'https://github.com/diem/diem/blob/main/json-rpc/json-rpc-spec.md',
      label: 'JSON-RPC API',
    },
    {
      type: 'link',
      href: 'https://github.com/libra/client-sdk-python',
      label: 'Python SDK',
    },
    {
      type: 'link',
      href: 'https://github.com/libra/client-sdk-java',
      label: 'Java SDK',
    },
    {
      type: 'link',
      href: 'https://github.com/libra/client-sdk-go',
      label: 'Go SDK',
    },
    'core/diem-cli',
  ]),
  category('Tutorials', [
    'core/run-local-network',
    'core/query-the-blockchain',
    'core/my-first-client',
  ]),
  ...getReference(),
];

module.exports = Sidebar;
