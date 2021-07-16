// Turn off ESLint for this file because it's sent down to users as-is.
/* eslint-disable */
!function(){
  var enterpriseFields = [
    'enterpriseField',
  ];

  var vcFields = [
    'enterpriseAssets',
  ];

  var nonVcFields = [
    'enterpriseUserBase',
    'enterpriseCustomerBase',
  ];

  var b2bFields = [
    'enterpriseCustomerBase',
  ]

  var b2cFields = [
    'enterpriseUserBase',
  ]

  var nonVcFieldsRequired = [
    'enterpriseMarketCap',
    'enterpriseType'
  ]

  function showFields(fields, required) {
    for (var i = 0, fieldId; fieldId = fields[i]; i++) {
      var input = document.getElementById(fieldId);
      var labelSelector = 'label[for="' + fieldId + '"]';
      var label = document.querySelector(labelSelector);
      if (input) {
        input.parentElement.classList.remove('hidden');
        input.classList.remove('hidden');
        if (required) {
          input.required = true;
          if (label) {
             label.classList.add('required');
          }
        }
      }
    }
  }

  function hideFields(fields, required) {
    for (var i = 0, fieldId; fieldId = fields[i]; i++) {
      var input = document.getElementById(fieldId);
      var labelSelector = 'label[for="' + fieldId + '"]';
      var label = document.querySelector(labelSelector);
      if (input) {
        input.parentElement.classList.add('hidden');
        input.value = '';
        input.required = false;
        if (label) {
           label.classList.remove('required');
        }
      }
    }
  }

  function handleOrgTypeChange(val) {
    if (val === 'Enterprise') {
      showFields(enterpriseFields, true);
    } else {
      hideFields(enterpriseFields);
      hideFields(nonVcFields);
      hideFields(nonVcFieldsRequired);
      hideFields(vcFields);
    }
  }

  function handleEnterpriseChange(val) {
    if (val === 'VCIForg') {
      showFields(vcFields, true);
      hideFields(nonVcFields);
      hideFields(nonVcFieldsRequired);
    } else {
      hideFields(vcFields);
      showFields(nonVcFieldsRequired, true);
    }
  }

  function handleEnterpriseTypeChange(val) {
    if (val === 'B2B') {
      showFields(b2bFields, true);
      hideFields(b2cFields);
    } else {
      showFields(b2cFields, true);
      hideFields(b2bFields);
    }
  }

  // Do not add search on form pages
  const search = document.querySelector('.navSearchWrapper.reactNavSearchWrapper');
  if (search && document.forms.length > 0) {
    // The following does not work on IE 11: search.remove();
    search.outerHTML = "";
  }

  var orgInput = document.getElementById('organizationType');
  if (orgInput) {
    orgInput.addEventListener('change', function(event) {
      handleOrgTypeChange(orgInput.value);
    });
  }

  var enterpriseInput = document.getElementById('enterpriseField');
  if (enterpriseInput) {
    enterpriseInput.addEventListener('change', function(event) {
      handleEnterpriseChange(enterpriseInput.value);
    });
  }

  var enterpriseTypeInput = document.getElementById('enterpriseType');
  if (enterpriseTypeInput) {
    enterpriseTypeInput.addEventListener('change', function(event) {
      handleEnterpriseTypeChange(enterpriseTypeInput.value);
    });
  }

}();
