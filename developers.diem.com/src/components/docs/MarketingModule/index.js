import React from 'react';
import PropTypes from 'prop-types';

import styles from './styles.module.css';
import Arrow from 'img/marketing-arrow.svg';

const MarketingModule = ({ copy, cta, ctaLink, img }) => (
  <div className={styles.root}>
    <div className={styles.content}>
      <p>{copy}</p>
      {cta &&
        <a className={styles.cta} href={ctaLink}>
          <span className={styles.join}>{cta}</span>
          <span className={styles.arrow}>
            <Arrow />
          </span>
        </a>
      }
    </div>
    <img alt="Marketing Module Image" src={img} />
  </div>
);

MarketingModule.propTypes = {
  copy: PropTypes.string.isRequired,
  cta: PropTypes.string,
  ctaLink: PropTypes.string,
  img: PropTypes.string.isRequired,
};

export default MarketingModule;
