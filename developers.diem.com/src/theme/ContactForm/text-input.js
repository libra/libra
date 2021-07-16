import React from 'react';

const getInput = (id, inputProps) => {
  const type = inputProps.type || 'text';
  if (type === 'textarea') {
    return <textarea id={id} type="text" {...inputProps} />;
  } else {
    return <input id={id} type="text" {...inputProps} />;
  }
};

/**
 * Input element. The type defaults to "text" but you can pass in any type
 * to override it. Except for "label" all the props are passed directly to
 * the input component.
 *
 * Here's an example of adding an email input:
 *
 * <TextInput label="Email" className="my-class" type="email" />
 *
 */
const TextInput = ({ label, id, ...inputProps }) => {
  const labelClass = inputProps.required ? 'required' : '';
  const extraClassName = inputProps.className || '';

  return (
    <div className={`inputGroup ${extraClassName}`}>
      <label className={labelClass} htmlFor={id}>{label}</label>
      {getInput(id, inputProps)}
    </div>
  );
};

export default TextInput;
