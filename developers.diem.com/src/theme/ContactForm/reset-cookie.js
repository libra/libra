import React, {useState} from 'react';

import Modal from './Modal';

const resetCookie = () => {
  document.cookie = `${window.trackingCookieConsent}=; Max-Age=0; path=/; domain=`;
  document.cookie = `${window.trackingCookieConsent}-legacy=; Max-Age=0`;
  location.reload();
};

const ResetCookie = ({ baseUrl }) => {
  const [showModal, setShowModal] = useState(true);

  return (
    <Modal showModal={showModal} setShowModal={setShowModal}>
      <h2>Please enable cookies to use this form.</h2>
      <div className="buttonWrapper">
        <a className="button secondary" onClick={resetCookie}>
          Click to reset cookies
        </a>
        <a className="button secondary" href="/">
          Return to homepage
        </a>
      </div>
    </Modal>
  );
};

export default ResetCookie;
