import React from 'react';
import PropTypes from 'prop-types';

import BaseContainer from '../BaseContainer';
import {WithBackgroundImage} from 'diem-docusaurus-components';

import classnames from 'classnames';
import styles from './styles.module.css';

const SimpleTextCard = ({ bolded, icon, iconDark, overlay, smallerImage, title, to }) => (
  <BaseContainer className={styles.root} overlay={overlay} to={to}>
    <WithBackgroundImage
      className={classnames(styles.image, {
        [styles.smaller]: smallerImage,
      })}
      imageLight={icon}
      imageDark={iconDark}
    />
    <span className={classnames(styles.title, {
      [styles.bolded]: bolded
    })}>
      {title}
    </span>
  </BaseContainer>
);

SimpleTextCard.propTypes = {
  bolded: PropTypes.bool,
  icon: PropTypes.string.isRequired,
  iconDark: PropTypes.string,
  overlay: PropTypes.string,
  smallerImage: PropTypes.bool,
  title: PropTypes.string.isRequired,
  to: PropTypes.string,
};

export default SimpleTextCard;
