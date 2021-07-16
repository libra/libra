import React from 'react';

import ArrowLeft from 'img/shared/arrow-left.svg';
import ArrowRight from 'img/shared/arrow-right.svg';

import classnames from 'classnames';
import styles from './styles.module.css';

const Pagination = ({metadata}) => {
  const previousLink = metadata;

  if (!metadata.previous && !metadata.next) {
    return null;
  }

  return (
    <div className={styles.pagination}>
      <a
        className={classnames(styles.previous, {
          [styles.disabled]: !metadata.previous,
        })}
        href={metadata.previous && metadata.previous.permalink}
      >
        <ArrowLeft />
        <span>Previous</span>
      </a>
      <a
        className={classnames(styles.next, {
          [styles['disabled']]: !metadata.next,
        })}
        href={metadata.next && metadata.next.permalink}
      >
        <span>Next</span>
        <ArrowRight />
      </a>
    </div>
  );
};

export default Pagination;
