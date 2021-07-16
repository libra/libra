import React from 'react';

export default () => {
  if (typeof window !== 'undefined') {
    const slug = location.pathname.slice(location.pathname.lastIndexOf('/')+1);
    window.location = 'https://diem.com/en-US/blog/' + slug;
  }

  return null;
};
