import React from 'react';
import Tabs from '@theme/Tabs';

import styles from './styles.module.css';

const MultiStepSnippet = props => {
  return (
    <div className={styles.root}>
      <Tabs {...props} />
    </div>
  );
};

export default MultiStepSnippet;
