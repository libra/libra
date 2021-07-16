const {categoryBoilerplate, getReference, standaloneLink} = require('./components');

const Sidebar = [
  ...categoryBoilerplate('technical-papers/overview', 'document'),
  standaloneLink('technical-papers/move-paper'),
  standaloneLink('technical-papers/state-machine-replication-paper'),
  standaloneLink('technical-papers/the-diem-blockchain-paper'),
  standaloneLink('technical-papers/jellyfish-merkle-tree-paper'),
  ...getReference(),
];

module.exports = Sidebar;
