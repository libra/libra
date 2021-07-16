const {category, categoryBoilerplate, getReference} = require('./components');

const Sidebar = [
  ...categoryBoilerplate('node/overview', 'node-operators'),
  category('Basics', [
    'node/nodes',
  ]),
  category('Getting Started', [
    'node/config-deploy-fn',
  ]),
  category('Tutorials', [
    'node/run-local-network',
  ]),
  ...getReference(),
];

module.exports = Sidebar;
