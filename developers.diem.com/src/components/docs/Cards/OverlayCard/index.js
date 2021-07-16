import React from 'react';
import PropTypes from 'prop-types';

import BaseContainer from '../BaseContainer';
import {WithBackgroundImage} from 'diem-docusaurus-components';

import styles from './styles.module.css';

const OverlayCard = ({ description, icon, iconDark, overlay, title, to }) => (
  <BaseContainer className={styles.root} overlay={overlay} to={to}>
    <div className={styles.circleOverlay} />
    <div className={styles.contents}>
      <WithBackgroundImage
        className={styles.image}
        imageLight={icon}
        imageDark={iconDark}
      />
      <div className={styles.textContainer}>
        <span className={styles.title}>{title}</span>
        <p className={styles.description}>{description}</p>
      </div>
    </div>
  </BaseContainer>
);

OverlayCard.propTypes = {
  description: PropTypes.string,
  icon: PropTypes.string.isRequired,
  iconDark: PropTypes.string,
  overlay: PropTypes.string,
  overlay: PropTypes.string,
  title: PropTypes.string.isRequired,
  to: PropTypes.string,
};

export default OverlayCard;
