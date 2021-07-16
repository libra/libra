import React, {useEffect, useState} from 'react';

import Modal from './Modal';

const EnableCookies = ({ baseUrl }) => {
  const [showModal, setShowModal] = useState(true);

  return (
    <Modal showModal={showModal} setShowModal={setShowModal}>
      <h2>Please enable cookies to use this form. You can do so by enabling using the banner below.</h2>
      <div className="buttonWrapper">
        <a className="button secondary" onClick={() => setShowModal(false)}>
          Close
        </a>
      </div>
    </Modal>
  );
};

export default EnableCookies;
