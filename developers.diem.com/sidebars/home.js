const {getReference} = require('./components');

const Sidebar = [
  {
    type: 'doc',
    id: 'welcome-to-diem',
    customProps: {
      classNames: ['home'],
      icon: 'img/home.svg',
      iconDark: 'img/home-dark.svg',
    },
  },
  {
    type: 'category',
    label: 'Topics',
    items: [
      {
        type: 'ref',
        id: 'core/overview',
        customProps: {
          classNames: ['iconIndented'],
          icon: 'img/core-contributors.svg',
          iconDark: 'img/core-contributors-dark.svg',
        },
      },
      {
        type: 'ref',
        id: 'node/overview',
        customProps: {
          classNames: ['iconIndented'],
          icon: 'img/node-operators.svg',
          iconDark: 'img/node-operators-dark.svg',
        },
      },
      {
        type: 'ref',
        id: 'wallet-app/overview',
        customProps: {
          classNames: ['iconIndented'],
          icon: 'img/wallet-app.svg',
          iconDark: 'img/wallet-app-dark.svg',
        },
      },
      {
        type: 'ref',
        id: 'merchant/overview',
        customProps: {
          classNames: ['iconIndented'],
          icon: 'img/merchant-solutions.svg',
          iconDark: 'img/merchant-solutions-dark.svg',
        },
      },
      {
        type: 'ref',
        id: 'move/overview',
        customProps: {
          classNames: ['iconIndented'],
          icon: 'img/move.svg',
          iconDark: 'img/move-dark.svg',
        },
      },
    ],
  },
  ...getReference('primary'),
];

module.exports = Sidebar;
