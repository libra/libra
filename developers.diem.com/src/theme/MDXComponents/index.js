import React from 'react';
import NativeComponents from '@theme-original/MDXComponents';
import DocComponents from 'components/docs';

import Link from 'src/components/Link';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

const ThemeComponents = {
  a: Link,
  Tabs,
  TabItem,
};

export default Object.assign(NativeComponents, DocComponents, ThemeComponents);
