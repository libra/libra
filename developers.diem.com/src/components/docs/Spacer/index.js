import React from 'react';
import PropTypes from 'prop-types'

import styles from './styles.module.css';

const Spacer = ({size}) => (
  <div className={styles[size]} />
);

Spacer.defaultProps = {
  size: 'md',
};

Spacer.propTypes = {
  size: PropTypes.oneOf(['sm', 'md', 'lg']),
};

export default Spacer;
