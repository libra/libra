import React, {useEffect, useState} from 'react';
import styles from './styles.module.css';

import useThemeContext from '@theme/hooks/useThemeContext';

const ID = "wave-background";

const setWaveHeight = setHeight => {
  const container = document.querySelector('main');
  const image = document.querySelector(`#${ID} img`);
  const wave = document.getElementById(ID);

  const totalHeight = container.clientHeight;
  const imageHeight = image.clientHeight;
  const distanceFromTop = wave.offsetTop;
  const internalOffset = eval(styles['total-offset']);

  setHeight(totalHeight - distanceFromTop - imageHeight - internalOffset);
};

const WaveBackground = () => {
  const {isDarkTheme} = useThemeContext();
  const [height, setHeight] = useState(0);

  const url = isDarkTheme ? '/img/docs/wave-top-dark.svg' : '/img/docs/wave-top.svg';

  useEffect(() => {
    setWaveHeight(setHeight);

    const observer = new ResizeObserver(() => setWaveHeight(setHeight));
    const main = document.querySelector('main');
    observer.observe(main);

    return () => observer.unobserve(main);
  });

  return (
    <div className={styles.root} id={ID}>
      <div>
        <img src={url} />
        <div className={styles.rectangle} style={{ height }} />
      </div>
    </div>
  );
};

export default WaveBackground;
