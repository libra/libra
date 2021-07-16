// Turn off ESLint for this file because it's sent down to users as-is.
/* eslint-disable */

!function(){

  function testSegment() {
    // Only test for segment (and open the modal) when there's a form on the page
    if (!document.forms.length) {
      return;
    }

    const request = new XMLHttpRequest();
    request.onreadystatechange = function() {
      if (request.readyState == 4 && request.status === 0) {
        toggleAdBlockModal(true)
      }
    }
    request.open('POST','https://api.segment.io/v1/p');
    request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    request.send(null);
  }

  /**
   * Find the form on the loaded page and send segment the form data on submit
   */
  testSegment();
  const forms = document.forms;
  for (let i = 0; i < forms.length; i++) {
    const form = forms[i];
    trackFormData(form);
  }

  function toggleEnabledFormButton(on) {
    const button = document.querySelector("button[type='submit']")
    if (on) {
      button.setAttribute("disabled", "disabled");
    } else {
      button.removeAttribute("disabled");
    }
  }

  function toggleAdBlockModal(on) {
    window.toggleAdBlockModal(on);
  }

  /**
   * Get the Segment event name by using the form's ID.
   *
   * Segment allows you to track by events and eventually retire an event name.
   * Being specific with an event name will help us maintain the full lifecycle
   * of events.
   */
  function getTrackFormEventName(form) {
    switch (form.id) {
      case 'partnerForm':
        return 'Partner Form Submit';
      case 'newsletterForm':
        return 'Newsletter Form Submit';
      default:
        return 'Form Submit';
    }
  }

  /**
   * Get all the input and select fields from a form.
   */
  function getFormFields(form) {
    const fields = [];
    // Iterate over the form controls
    for (i = 0; i < form.elements.length; i++) {
      const el = form.elements[i];
      if (el.nodeName === 'INPUT' ||
          el.nodeName === 'SELECT' ||
          el.nodeName === 'TEXTAREA') {
        fields.push(el);
      }
    }
    return fields;
  }

  /**
   * Filter an object by an array of fields passed in. If a mapping
   * is passed in we change the key.
   */
  function filterFields(data, fields, mapping) {
    const filtered = Object.keys(data)
      .filter(function(key) {
        return fields.indexOf(key) >= 0;
      })
      .reduce(function(obj, key) {
        const mapKey = (mapping && mapping[key]) || key;
        obj[mapKey] = data[key];
        return obj;
      }, {});

    return filtered;
  }

  function addGroup(data) {
    const fields = [
      'organizationId',
      'organizationHQ',
      'organizationRevenue',
      'organizationGeoCoverage',
      'organizationType',
      'organizationWebsite',
      'enterpriseField',
      'enterpriseUserBase',
      'enterpriseCustomerBase',
      'enterpriseMarketCap',
      'enterpriseAssets',
    ];

    const filteredData = filterFields(data, fields);
    const groupId = filteredData.organizationId;
    filteredData.name = groupId;

    analytics.group(groupId, filteredData);
  }

  function addIndentity(data, form) {
    const fields = [
      'email',
      'firstName',
      'lastName',
      'phone',
      'title',
      'formId',
      'organizationId',
      'companyId'
    ];

    // Using organizationId here will set off some automagic segment configuration
    // causing the call to Zendesk to fail. organizationId needs to be an int.
    const mapping = {
      organizationId: 'orgName'
    };

    const filteredData = filterFields(data, fields, mapping);
    analytics.identify(filteredData.email, filteredData);
  }

  /**
   * Sends the submitted form data to segment in a track call.
   */

  function getMultiSelectValues(select) {
    var result = [];
    var options = select && select.options;
    var opt;

    for (var i=0; i < options.length; i++) {
      opt = options[i];

      if (opt.selected) {
        result.push(opt.value || opt.text);
      }
    }
    return result;
  }

  function trackFormData(form) {
    // FIXME: This needs to be in sync with the siteConfig
    const baseUrl = '/docs/';

    form.addEventListener('submit', function(e) {
      e.preventDefault()
      toggleEnabledFormButton(false);

      const fields = getFormFields(form);
      const data = {
        formId: form.id,
      };

      fields.forEach(function(field) {
        data[field.id] = field.value;

        if (field.multiple) {
          data[field.id] = getMultiSelectValues(field);
        }
      });

      const trackName = getTrackFormEventName(form);
      // Dump the raw form data into the event.
      analytics.track(trackName, data)

      if (form.id === 'newsletterForm') {
        // A name is required for adding users to Zendesk
        data.name = data.email;
      }

      addIndentity(data, form);

      if (data.organizationId) {
        addGroup(data);
      }

      setTimeout(function() {
        toggleEnabledFormButton(true);
        window.location.replace('/form-thanks');
      }, 500);

    })
  }
}();
