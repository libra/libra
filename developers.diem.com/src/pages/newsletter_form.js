import React from 'react';

import countryCodes from '@theme/ContactForm/country-codes';
import FormContainer from '@theme/ContactForm/form-container';
import Layout from '@theme/Layout';

const formFields = [{
  items: [{
    id: 'email',
    label: 'Email',
    type: 'email',
    required: true
  }, {
    id: 'interest',
    label: 'Interest',
    type: 'select',
    required: false,
    options: [{
      value: 'Protocol',
      text: 'Protocol'
    }, {
      value: 'Application development',
      text: 'Application development'
    }, {
      value: 'Both?',
      text: 'Both?'
    }]
  }, {
    id: 'background',
    label: 'Background',
    type: 'select',
    required: false,
    options: [{
      value: 'BlockchainDeveloper',
      text: 'Blockchain Developer'
    }, {
      value: 'Researcher',
      text: 'Researcher',
    }, {
      value: 'InstitutionalDeveloper',
      text: 'Institutional Developer'
    }, {
      value: 'dAppsDeveloper',
      text: 'Apps Developer'
    }, {
      value: 'Other',
      text: 'Other'
    }]
  }, {
    id: 'country',
    label: 'Country',
    type: 'select',
    required: false,
    options: countryCodes.map(country => {
      return {
        value: country.abbreviation,
        text: country.country
      };
    })
  }]
}];

export default props => {
  return (
    <Layout containWidth={false}>
      <FormContainer
        {...props}
        fields={formFields}
        formId="newsletterForm"
        title="Newsletter Sign-up"
        subtitle="Please complete the form below and hit submit."
      />
    </Layout>
  );
}
