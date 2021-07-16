import React from 'react';
import PropTypes from 'prop-types';
import Terminal, {
  CommandForms as DefaultCommands,
} from '@libra-opensource/diem-cli';

import './styles.css';
import classnames from 'classnames';
import styles from './styles.module.css';

const getAvailableCommands = (command, commands) => {
  if (command && commands) {
    throw 'command and commands can not be simultaneously set on a CLI';
  } else if (!commands && !command) {
    return DefaultCommands;
  } else if (command) {
    return [command];
  } else {
    return commands;
  }
};

const CLI = ({ command, commands, isEmbedded, withTutorial }) => {
  const availableCommands = getAvailableCommands(command, commands);

  return (
    <Terminal
      availableCommands={availableCommands}
      className={classnames("cli", styles.root, {
        "embedded-cli": isEmbedded,
      })}
      withTutorial={withTutorial}
    />
  );
};

CLI.propTypes = {
  /*
   * Additional prop to simplify usage when there
   * is only one command
   */
  command: PropTypes.object,
  commands: PropTypes.arrayOf(PropTypes.object),
  isEmbedded: PropTypes.bool,
  withTutorial: PropTypes.bool,
};

CLI.defaultProps = {
  isEmbedded: true,
};

export default CLI;
