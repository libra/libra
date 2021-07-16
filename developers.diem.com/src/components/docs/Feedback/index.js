import React, {useContext, useState} from 'react';

import { CookieContext } from 'diem-docusaurus-components';

import ThumbsUp from 'img/thumbs-up.svg';
import ThumbsDown from 'img/thumbs-down.svg';

import styles from './styles.module.css';

const sendFeedback = value => {
  analytics.track('feedback', {
    type: 'pageHelpful',
    value,
    section: 'endOfPage'
  });
};

const Feedback = () => {
  const [feedbackSent, setFeedbackSent] = useState(false);
  const {cookiesEnabled} = useContext(CookieContext.Context);

  const handleFeedback = value => {
    setFeedbackSent(true);
    sendFeedback(value);
  };

  if (!cookiesEnabled) {
    return null;
  } else if (feedbackSent) {
    return (
      <div className={styles.root}>
        <span>Thank you for your feedback!</span>
      </div>
    );
  }

  return (
    <div className={styles.root}>
      <span>Was this page helpful?</span>
      <a onClick={() => handleFeedback(10)}><ThumbsUp /></a>
      <a onClick={() => handleFeedback(0)}><ThumbsDown /></a>
    </div>
  );
};

export default Feedback;
