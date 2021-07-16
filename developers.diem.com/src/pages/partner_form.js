import React from 'react';

import countryCodes from '@theme/ContactForm/country-codes';
import Layout from '@theme/Layout';
import FormContainer from '@theme/ContactForm/form-container';

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
    required: true
  }, {
    id: 'lastName',
    label: 'Last name',
    type: 'text',
    required: true
  }, {
    id: 'title',
    label: 'Title',
    type: 'text',
    required: true
  }, {
    id: 'phone',
    label: 'Phone number',
    type: 'tel',
    required: true
  }, {
    id: 'email',
    label: 'Email address',
    type: 'email',
    required: true
  }]
},{
  items: [{
    id: 'interestsAndExpertise',
    label: 'Describe your goals in working with the Diem project and the expertise you’d bring to the network either as a member or in any other capacity (1000 characters max)',
    type: 'textarea',
    maxLength: '1000',
    rows: '5',
    required: true
  }, {
    id: 'projects',
    label: 'Please provide a list of your current projects related to Blockchain, include links (1000 characters max)',
    type: 'textarea',
    maxLength: '1000',
    rows: '5',
    required: true
  }]
},{
  items: [{
    id: 'organizationId',
    label: 'Organization name',
    type: 'text',
    required: true
  }, {
    id: 'organizationWebsite',
    label: 'Organization website',
    type: 'text',
    required: true
  }]
 }, {
  items: [{
    id: 'organizationRevenue',
    label: 'Organization revenue',
    type: 'select',
    required: true,
    options: [{
      value: 'lessThan5M',
      text: '<5M USD'
    }, {
      value: '5M-25M',
      text: '5M - 25M USD'
    }, {
      value: '25M-50M',
      text: '25M - 50M USD'
    }, {
      value: '50M-100M',
      text: '50M - 100M USD'
    }, {
      value: 'greaterThan100MUSD',
      text: '>100M USD'
    }]
  }, {
    id: 'organizationType',
    label: 'Organization type',
    type: 'select',
    required: true,
    options: [{
      value: 'Enterprise',
      text: 'Enterprise'
    }, {
      value: 'NGO',
      text: 'NGO'
    }, {
      value: 'Multilateral',
      text: 'Multilateral'
    }, {
      value: 'Social impact partner',
      text: 'Social impact partner'
    }, {
      value: 'University',
      text: 'University'
    }]
  }, {
    id: 'enterpriseField',
    label: 'Organization field',
    type: 'select',
    required: false,
    className: 'hidden',
    options: [{
      value: 'Finance',
      text: 'Finance'
    }, {
      value: 'Internet',
      text: 'Internet'
    }, {
      value: 'Technology',
      text: 'Technology'
    }, {
      value: 'Retail',
      text: 'Retail'
    }, {
      value: 'MediaAndEntertainment',
      text: 'Media & Entertainment'
    }, {
      value: 'Telecommunications',
      text: 'Telecommunications'
    }, {
      value: 'ConsultingAndAudit',
      text: 'Consulting and Audit'
    }, {
      value: 'CryptoBlockchain',
      text: 'Crypto/Blockchain'
    }, {
      value: 'VCIForg',
      text: 'VC/IF org'
    }, {
      value: 'Industry',
      text: 'Industry'
    }]
  }, {
    id: 'enterpriseType',
    label: 'B2B or B2C?',
    type: 'select',
    required: true,
    className: 'hidden',
    options: [{
      value: 'B2B',
      text: 'B2B'
    }, {
      value: 'B2C',
      text: 'B2C'
    }]
  }, {
    id: 'enterpriseUserBase',
    label: 'User base (B2C)',
    type: 'select',
    required: false,
    className: 'hidden',
    options: [{
      value: 'lessThan5M',
      text: '<5M'
    }, {
      value: '5M-20M',
      text: '5M - 20M'
    }, {
      value: '20M-100M',
      text: '20M - 100M'
    }, {
      value: 'greaterThan100M',
      text: '>100M'
    }]
  }, {
    id: 'enterpriseCustomerBase',
    label: 'Merchants/customer base (B2B)',
    type: 'select',
    required: false,
    className: 'hidden',
    options: [{
      value: 'lessThan10k',
      text: '<10k'
    }, {
      value: '10k-100k',
      text: '10k - 100k'
    }, {
      value: 'greaterThan100k',
      text: '>100k'
    }]
  }, {
    id: 'enterpriseMarketCap',
    label: 'Market cap',
    type: 'select',
    required: false,
    className: 'hidden',
    options: [{
      value: 'lessThan100M',
      text: '<100M'
    }, {
      value: '100M-500M',
      text: '100M - 500M'
    }, {
      value: '500M-1B',
      text: '500M - 1B'
    }, {
      value: 'greaterThan1B',
      text: '>1B'
    }]
  }, {
    id: 'enterpriseAssets',
    label: 'Assets under management (only for VC/IFs)',
    type: 'select',
    required: false,
    className: 'hidden',
    options: [{
      value: 'lessThan500M',
      text: '<500M'
    }, {
      value: '500M-1B',
      text: '500M - 1B'
    }, {
      value: 'greaterThan1B',
      text: '>1B'
    }]
  }]
 }, {
  items: [{
    id: 'organizationGeoCoverage',
    label: 'Geographic coverage (please select all that apply to you)',
    type: 'select',
    required: true,
    multiple: true,
    className: 'selectMulti',
    placeholderText: 'Hold down ctrl or cmd to select multiple options',
    options: [{
      value: 'Africa',
      text: 'Africa'
    }, {
      value: 'Asia',
      text: 'Asia'
    }, {
      value: 'Central America',
      text: 'Central America'
    }, {
      value: 'Europe',
      text: 'Europe'
    }, {
      value: 'Middle East',
      text: 'Middle East'
    }, {
      value: 'North America',
      text: 'North America'
    }, {
      value: 'Oceania',
      text: 'Oceania'
    }, {
      value: 'South America',
      text: 'South America'
    }, {
      value: 'Caribbean',
      text: 'Caribbean'
    }]
  }, {
    id: 'organizationHQ',
    label: 'Organization HQ',
    type: 'select',
    required: true,
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
        formId="partnerForm_2019-10-14"
        fields={formFields}
        title="Partner Interest"
        subtitle="Please complete the form below and hit submit."
      />
    </Layout>
  );
};
