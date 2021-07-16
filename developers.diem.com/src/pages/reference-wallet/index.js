import React from 'react';
import Layout from '@theme/Layout';
import styles from './styles.module.css';

export default props => {
  return (
    <Layout>
      <div className={styles.root}>
        <iframe
          className={styles.walletApp}
          src="https://demo-wallet.diem.com/login"
        />
      </div>
    </Layout>
  );
}
