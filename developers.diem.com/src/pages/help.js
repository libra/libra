import React from 'react';

import Layout from '@theme/Layout';

import 'CSS/forms.css';

const Help = props => {
  const docUrl = doc => `/docs/${doc}`;

  const supportLinks = [
    {
      content:
        <p>
          Learn more using the <a href={docUrl('')}> documentation on this site</a>
        </p>,
      title: 'Browse Docs',
    },
    {
      content: 'Ask questions about the documentation and project',
      title: 'Join the community',
    },
    {
      content: "Find out what's new with this project",
      title: 'Stay up to date',
    },
  ];

  return (
    <Layout>
      <div className="post">
        <header className="postHeader">
          <h1>Need help?</h1>
        </header>
        <p>This project is maintained by a dedicated group of people.</p>
        <div id="columnContainer">
          {supportLinks.map(({content, title}) => (
            <div>
              <h1>{title}</h1>
              <p>{content}</p>
            </div>
          ))}
        </div>
        <div contents={supportLinks} layout="threeColumn" />
      </div>
    </Layout>
  );
};

export default Help;
