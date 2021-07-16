/**
 * Copyright (c) The Diem Core Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
import React from 'react';
import Layout from '@theme/Layout';

const papersLocation = '/papers';

// Metadata on the paper versions. Whenever a new paper is added just add the
// new date at the top of the corresponding "dates" array.
// TODO (joshua): Automate the list of papers by looking at the directories.
const paperMeta = {
  'The Diem Blockchain': {
    abstractUrl: '/docs/technical-papers/the-diem-blockchain-paper/',
    paperBase: `${papersLocation}/the-diem-blockchain`,
    dates: ['2020-05-26', '2020-04-09', '2019-09-26', '2019-09-18', '2019-06-25'],
    imgLoc: '/papers/illustrations/diem-blockchain-pdf.png',
    imgAlt: 'The Diem Blockchain PDF Download',
  },
  'Move Programming Language': {
    abstractUrl: '/docs/technical-papers/move-paper/',
    paperBase: `${papersLocation}/diem-move-a-language-with-programmable-resources`,
    dates: ['2020-05-26', '2020-04-09', '2019-09-26', '2019-06-18'],
    imgLoc: '/papers/illustrations/move-language-pdf.png',
    imgAlt: 'Move: A Language With Programmable Resources PDF Download',
  },
  'State Machine Replication': {
    abstractUrl: '/docs/technical-papers/state-machine-replication-paper/',
    paperBase: `${papersLocation}/diem-consensus-state-machine-replication-in-the-diem-blockchain`,
    dates: [
      '2020-05-26',
      '2020-04-09',
      '2019-11-08',
      '2019-10-24',
      '2019-09-26',
      '2019-06-28',
    ],
    imgLoc: '/papers/illustrations/state-machine-pdf.png',
    imgAlt: 'State Machine Replication in the Diem Blockchain PDF Download',
  },
  'Jellyfish Merkle Tree': {
    abstractUrl: '/docs/technical-papers/jellyfish-merkle-tree-paper',
    paperBase: `${papersLocation}/jellyfish-merkle-tree`,
    dates: [
      '2021-01-14',
    ],
    imgLoc: '/img/docs/jellyfish-merkle-tree-pdf.png',
    imgAlt: 'Jellyfish Merkle Tree Paper',
  },
};

/**
 * Get the sections for each of the papers in the paperMetadata.
 */
function getPapers() {
  const paperSections = [];

  for (const paper in paperMeta) {
    const metadata = paperMeta[paper];

    const dates = Array.from(metadata.dates);
    const current = dates.shift();
    const oldPapers = dates.map(function (date, idx) {
      return (
        <li key={`${metadata.paperBase}--${idx}`}>
          <a href={`${metadata.paperBase}/${date}.pdf`}>{date}</a>
        </li>
      );
    });

    paperSections.push(
      <section key={metadata.paperBase}>
        <h2>
          <a href={metadata.abstractUrl}>{paper}</a>
        </h2>
        <ul>
          <li>
            <a href={`${metadata.paperBase}/${current}.pdf`}>{`Latest version (${current})`}</a>
          </li>
          {oldPapers}
        </ul>
      </section>,
    );
  }

  return paperSections;
}

export default props => {
  return (
    <Layout>
      <div className="archiveContainer">
        <h1>Publication Archive</h1>
        {getPapers()}
      </div>
    </Layout>
  );
}
