import React from 'react';
import PropTypes from 'prop-types'

import styles from './styles.module.css';

const CardsWrapper = ({ cardsPerRow, children, title }) => (
  <>
    {title && <h2>{title}</h2>}
    <div className={`${styles.root} ${styles[`rowOf${cardsPerRow}`]}`}>
      {children}
    </div>
  </>
);

CardsWrapper.propTypes = {
  cardsPerRow: PropTypes.number,
  title: PropTypes.string,
};

CardsWrapper.defaultProps = {
  cardsPerRow: 3,
};

export default CardsWrapper;
