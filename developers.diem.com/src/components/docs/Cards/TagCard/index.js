import React from 'react';
import PropTypes from 'prop-types';

import BaseContainer from '../BaseContainer';
import {WithBackgroundImage} from 'diem-docusaurus-components';

import styles from './styles.module.css';

const TagCard = ({ icon, iconDark, tags, title, to }) => (
  <BaseContainer className={styles.root} to={to}>
    <WithBackgroundImage
      className={styles.image}
      imageLight={icon}
      imageDark={iconDark}
    />
    <div className={styles.textContainer}>
      <span className={styles.title}>{title}</span>
      <div>
        {tags.map(tag =>
          <span className={styles.tag} key={tag}>{tag}</span>
        )}
      </div>
    </div>
  </BaseContainer>
);

TagCard.propTypes = {
  icon: PropTypes.string.isRequired,
  iconDark: PropTypes.string,
  tags: PropTypes.array.isRequired,
  title: PropTypes.string.isRequired,
};

export default TagCard;
