import React from 'react';
import TextInput from './text-input';
import SelectInput from './select-input';

/**
 * Get the legend if "title" was passed in
 */
const getLegend = (title) => {
  return title ? (<legend>{title}</legend>) : null;
}

/**
 * Get the inputs from the config
 */
const getInputs = (items) => {
  return items.map(item => {
    // FIXME: Maybe include the class in the config. The goal is to
    // remove the need to parse a string.
    const Input = item.type === 'select' ? SelectInput : TextInput;
    return <Input key={`input-${item.id}`} {...item} />;
  });
}


const FieldSet = ({ title, items }) => {
  return (
    <fieldset>
      {getLegend(title)}
      {getInputs(items)}
    </fieldset>
  );
};

export default FieldSet;
