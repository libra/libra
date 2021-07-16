import React, {useEffect, useState} from 'react';

import ExecutionEnvironment from '@docusaurus/ExecutionEnvironment';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

import DisableAdblock from './disable-adblock';
import EnableCookies from './enable-cookies';
import FieldSet from './fieldset';
import FormHeader from './form-header';
import ResetCookie from './reset-cookie';
import utils from 'diem-docusaurus-components/src/utils';

const {getCookie} = utils;

import 'CSS/forms.css';

const getFields = (fields) => {
  return fields.map((config, idx) => {
    return <FieldSet key={`form-fieldset-${idx}`} {...config} />;
  });
};

const getForm = (formId, fields) => {
  if (!formId) {
    return null;
  }

  return (
    <div className="formWrapper">
      <form id={formId}>
        {getFields(fields)}
        <div className="formControlGroup">
          <button className="button right" type="submit">Submit</button>
        </div>
      </form>
    </div>
  );
}


const FormContainer = ({ children, fields, formId, subtitle, title }) => {
  const segmentPermissionCookie = ExecutionEnvironment.canUseDOM
    ? getCookie(window.trackingCookieConsent)
    : undefined;

  useEffect(() => {
    /*
     * In the edge case where a user has not yet accepted the cookie policy
     * and does so while on this page. We need to have the segment form script
     * even though it wouldn't have loaded on the initial load.
     * When the cookie is accepted, window.loadSegment will load again, and if
     * window.isFormPage is true, the form script will then be loaded.
     */
    window.isFormPage = true;

    if (segmentPermissionCookie !== 'true') {
      return;
    }

    window.loadSegmentFormScript();
  }, []);
  const {siteConfig: {baseUrl}} = useDocusaurusContext();

  /**
   * Get the className and src props for the img elements.
   */
  const getImageProps = (className, image) => {
    return {
      className: `formBgImage ${className}`,
      src: `${baseUrl}img/${image}`
    };
  };

  return (
    <div className="mainContainer formPage">
      {segmentPermissionCookie === undefined && <EnableCookies />}
      {segmentPermissionCookie === 'false' && <ResetCookie />}
      <DisableAdblock baseUrl={baseUrl} />
      <FormHeader title={title} subtitle={subtitle} />
      <div className="wrapper">
        <img {...getImageProps('formIcon', 'form-icon.svg')} />
        <img {...getImageProps('bgCircleLeft', 'bg-circle-whole.svg')} />
        <img {...getImageProps('bgCircleBottom', 'bg-circle-half.svg')} />
        <img {...getImageProps('bgCircleRight', 'bg-circle-whole.svg')} />
        <div className="mainContainer documentContainer postContainer width-wrapper">
          {getForm(formId, fields)}
          {children}
        </div>
      </div>
    </div>
  );
};

export default FormContainer;
