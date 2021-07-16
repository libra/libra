import React from 'react';
import PropTypes from 'prop-types';

import useBaseUrl from '@docusaurus/useBaseUrl';

import BaseContainer from '../BaseContainer';

import classnames from 'classnames';
import styles from './styles.module.css';

const ColorCard = ({ color, icon, overlay, title, to, type, ...props }) => (
  <BaseContainer
    className={classnames(styles.root, styles[color], {
      [styles.snippetTab]: type === 'snippetTab',
      [styles.withOverlay]: type === 'snippetTab' && overlay,
    })}
    hasShadow={false}
    tabIndex={`"${type === 'snippetTab' && -1}"`}
    to={to}
    {...props}
  >
    {type === 'snippetTab' && overlay && (
      <div className={styles.overlay}>
        <span>{overlay}</span>
      </div>
    )}
    <div
      className={styles.image}
      style={{ backgroundImage: `url('${useBaseUrl(icon)}')` }}
    />
    <span className={styles.title}>{title}</span>
  </BaseContainer>
);

ColorCard.propTypes = {
  color: PropTypes.oneOf(['aqua', 'purpleDark', 'purpleLight']).isRequired,
  icon: PropTypes.string.isRequired,
  overlay: PropTypes.string,
  title: PropTypes.string.isRequired,
  to: PropTypes.string,
  type: PropTypes.oneOf(['default', 'snippetTab']),
};

ColorCard.defaultProps = {
  type: 'default',
};

export default ColorCard;
