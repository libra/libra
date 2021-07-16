import React from 'react';

import FormContainer from '@theme/ContactForm/form-container';
import Layout from '@theme/Layout';

/**
 * NOTE: These ids should map to the Segment Zendesk mapping.
 * https://segment.com/docs/destinations/zendesk/
 *
 * See: static/js/forms.js. This is a stateless form and all
 * the dynamic aspects are in the forms.js file.
 */
const formFields = [{
  items: [{
    id: 'firstName',
    label: 'First name',
    type: 'text',
    maxLength: '50',
    required: true
  }, {
    id: 'lastName',
    label: 'Last name',
    type: 'text',
    maxLength: '50',
    required: true
  }, {
    id: 'email',
    label: 'Email address',
    type: 'email',
    maxLength: '250',
    required: true
  }, {
    id: 'companyId',
    label: 'Company name',
    type: 'text',
    maxLength: '250',
    required: true
  },{
    id: 'comments',
    label: 'Describe your goals in working with the Diem project (1000 characters max)',
    type: 'textarea',
    maxLength: '1000',
    rows: '5',
    required: true
  }]
}];

export default props => {
  return (
    <Layout containWidth={false}>
      <FormContainer
        {...props}
        fields={formFields}
        formId="developerInterestForm_2020-04-17"
        title="Developer Application Form"
        subtitle="Please complete the form below and hit submit."
      />
    </Layout>
  );
}
