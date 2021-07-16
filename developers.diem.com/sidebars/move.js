const {category, categoryBoilerplate, getReference} = require('./components');

const Sidebar = [
  ...categoryBoilerplate('move/overview', 'move'),
  category('Start Here', [
    'move/move-introduction',
    'move/move-modules-and-scripts',
    'move/move-tutorial-creating-coins',
  ]),
  category('Primitive Types', [
    'move/move-integers',
    'move/move-bool',
    'move/move-address',
    'move/move-vector',
    'move/move-signer',
    'move/move-references',
    'move/move-tuples-and-unit',
  ]),
  category('Basic Concepts', [
    'move/move-variables',
    'move/move-abort-and-assert',
    'move/move-conditionals',
    'move/move-while-and-loop',
    'move/move-functions',
    'move/move-structs-and-resources',
    'move/move-constants',
    'move/move-generics',
    'move/move-equality',
    'move/move-uses-and-aliases',
  ]),
  category('Global Storage', [
    'move/move-global-storage-structure',
    'move/move-global-storage-operators',
  ]),
  category('Reference', [
    'move/move-standard-library',
    'move/move-coding-conventions',
  ]),
  ...getReference(),
];

module.exports = Sidebar;
