import React, {useState} from 'react';

import ExecutionEnvironment from '@docusaurus/ExecutionEnvironment';

import classnames from 'classnames';
import styles from './Modal/styles.module.css';

const DisableAdblock = ({ baseUrl }) => {
  const [showModal, setShowModal] = useState(false);

  // used in segmentForm.js
  if (ExecutionEnvironment.canUseDOM) {
    window.toggleAdBlockModal = setShowModal;
  }

  return (
    <div id="disable-ad-block" className={classnames("modal", {
      "visible": showModal,
    })} onClick={() => setShowModal(false)}>
      <div className={styles.outer} onClick={e => e.stopPropagation()}>
        <div className={styles.inner}>
          <img src={`${baseUrl}img/ab-icon@2x.svg`} alt="Adblock icon" />
          <h2>Please disable your ad blocker!</h2>
          <p>We get it... but it's necessary to submit the form.</p>
          <div className="buttonWrapper">
            <a id="disable-adblock-refresh" className="button secondary" href="">
              Refresh
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DisableAdblock;
