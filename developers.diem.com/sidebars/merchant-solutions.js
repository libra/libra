const {category, categoryBoilerplate, getReference} = require('./components');

const Sidebar = [
  ...categoryBoilerplate('merchant/overview', 'merchant-solutions'),
  category('Guides', [
    'merchant/merchant-guide',
  ]),
  category('Diem Reference Merchant', [
    category('Basics', [
      'merchant/intro-to-drm',
    ]),
    category('Getting Started', [
      'merchant/develop-drm',
    ]),
    category('Test', [
      'merchant/try-demo-merchant',
      'merchant/local-merchant-store',
      'merchant/payment-mgmt',
    ]),
  ]),
  ...getReference(),
];

module.exports = Sidebar;
