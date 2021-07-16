import React from 'react';

import Head from '@docusaurus/Head';
import isInternalUrl from '@docusaurus/isInternalUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useTOCHighlight from '@theme/hooks/useTOCHighlight';

import { OVERFLOW_CONTAINER_CLASS } from '@theme/Layout';

import Feedback from 'components/docs/Feedback';
import Pagination from './Pagination';
import { RightSidebar } from 'diem-docusaurus-components';

import classnames from 'classnames';
import styles from './styles.module.css';

function DocItem(props) {
  const {
    siteConfig: { url: siteUrl, title: siteTitle },
  } = useDocusaurusContext();
  const { content: DocContent } = props;
  const {
    frontMatter: {
      disable_pagination: disablePagination,
      hide_right_sidebar: hideRightSidebar,
      image: metaImage,
      keywords,
      hide_title: hideTitle,
      hide_table_of_contents: hideTableOfContents,
      wider_content: widerContent,
    },
    metadata,
    toc,
  } = DocContent;
  const { description, title, permalink, editUrl } = metadata;

  const metaTitle = title ? `${title} | ${siteTitle}` : siteTitle;
  let metaImageUrl = siteUrl + useBaseUrl(metaImage);
  if (!isInternalUrl(metaImage)) {
    metaImageUrl = metaImage;
  }

  return (
    <>
      <Head>
        <title>{metaTitle}</title>
        <meta property="og:title" content={metaTitle} />
        {description && <meta name="description" content={description} />}
        {description && (
          <meta property="og:description" content={description} />
        )}
        {keywords && keywords.length && (
          <meta name="keywords" content={keywords.join(',')} />
        )}
        {metaImage && <meta property="og:image" content={metaImageUrl} />}
        {metaImage && <meta property="twitter:image" content={metaImageUrl} />}
        {metaImage && (
          <meta name="twitter:image:alt" content={`Image for ${title}`} />
        )}
        {permalink && <meta property="og:url" content={siteUrl + permalink} />}
      </Head>
      <div className={classnames('container', styles.docItemWrapper)}>
        <div
          className={classnames('main-content', {
            [styles.fullWidthContent]: hideRightSidebar,
          })}
        >
          <div
            className={classnames(
              styles.docItemContainer,
              classnames({
                [styles.wider]: widerContent,
              })
            )}
          >
            <article>
              {!hideTitle && (
                <header>
                  <h1 className={styles.docTitle}>{title}</h1>
                </header>
              )}
              <div className="markdown">
                <DocContent />
              </div>
            </article>
            <Feedback />
            <span className={styles.community}>
              <a href="https://community.diem.com/">Ask the community</a> for
              support
            </span>
            {!disablePagination && <Pagination metadata={metadata} />}
          </div>
        </div>
        {!hideRightSidebar && <RightSidebar editUrl={editUrl} headings={toc} />}
      </div>
    </>
  );
}

export default DocItem;
