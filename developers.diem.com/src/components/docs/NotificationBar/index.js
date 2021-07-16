import React from 'react';

import styles from './styles.module.css';

const NotificationBar = ({children}) => (
  <div className={styles.root}>{children}</div>
);

export default NotificationBar;
