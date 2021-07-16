import React from 'react';
import PropTypes from 'prop-types';

import BaseContainer from '../BaseContainer';
import Link from 'src/components/Link';
import {WithBackgroundImage} from 'diem-docusaurus-components';

import classnames from 'classnames';
import styles from './styles.module.css';

const SDKCard = ({ bolded, docs, icon, iconDark, overlay, sdk, smallerImage, title, to }) => (
  <BaseContainer className={styles.root} overlay={overlay} to={to}>
    <div className={styles.left}>
      <img className={styles.icon} src={icon} />
    </div>
    <div className={styles.right}>
      <Link className={styles.sdk} href={sdk}>
        <WithBackgroundImage
          className={styles.buttonImage}
          imageLight="img/document.svg"
          imageDark="img/document-dark.svg"
        />
        <span className={styles.label}>SDK</span>
      </Link>
      {docs &&
        <Link className={styles.docs} href={docs}>
          <WithBackgroundImage
            className={styles.buttonImage}
            imageLight="img/roadmap.png"
            imageDark="img/reference-dark.svg"
          />
          <span className={styles.label}>Docs</span>
        </Link>
      }
    </div>
  </BaseContainer>
);

SDKCard.propTypes = {
  docs: PropTypes.string,
  icon: PropTypes.string.isRequired,
  iconDark: PropTypes.string,
  overlay: PropTypes.string,
  sdk: PropTypes.string.isRequired,
  to: PropTypes.string,
};

export default SDKCard;
