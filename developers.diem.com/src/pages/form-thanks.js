import React from 'react';

import Layout from '@theme/Layout';
import FormContainer from '@theme/ContactForm/form-container';
import FormHeader from '@theme/ContactForm/form-header';

import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

const FormThanks = () => {
  const {siteConfig: {baseUrl}} = useDocusaurusContext();

  return (
    <Layout containWidth={false}>
      <FormContainer title="Thank you!" subtitle="">
        <a className="button" href={baseUrl}>Return</a>
      </FormContainer>
    </Layout>
  );
};

export default FormThanks;
