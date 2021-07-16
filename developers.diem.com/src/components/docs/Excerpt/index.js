import React from 'react';
import PropTypes from 'prop-types';

import useBaseUrl from '@docusaurus/useBaseUrl';

import styles from './styles.module.css';

const Excerpt = ({children, image}) => {
  return (
    <div className={styles.root}>
      <div className={styles.content}>
        <div className={styles.imageContainer}>
          <img className={styles.image} src={useBaseUrl(image)} />
        </div>
        <div className={styles.text}>
          <p>
            {children}
          </p>
        </div>
      </div>
    </div>
  );
};

Excerpt.propTypes = {
  children: PropTypes.oneOfType([PropTypes.array, PropTypes.string]).isRequired,
  image: PropTypes.string.isRequired,
};

export default Excerpt;
