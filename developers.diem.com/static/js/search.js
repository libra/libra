// Turn off ESLint for this file because it's sent down to users as-is.
/* eslint-disable */
!function(){
  function addSearchElements() {
    const container = document.querySelector('nav ul.nav-site.nav-site-internal');
    const li = document.createElement('li');
    li.key = "search";
    li.className = "navSearchWrapper reactNavSearchWrapper"

    const input = document.createElement('input');
    input.type = 'text';
    input.id = 'search_input_react';
    input.placeholder = 'Search';
    input.title = 'Search';
    li.appendChild(input);
    container.appendChild(li);
  }

  document.addEventListener('DOMContentLoaded', (event) => {
    addSearchElements();
    const script = document.createElement('script');
    script.innerHTML = `
      var search = docsearch({
        appId: '70WKXLZ6RZ',
        apiKey: '7c82db8b8ceae28c1601f34346452f65',
        indexName: 'diem.github.io',
        inputSelector: '#search_input_react'
      });
    `;
    document.getElementsByTagName('head')[0].appendChild(script);

    document.addEventListener('keyup', function(e) {
      if (e.target !== document.body) {
        return;
      }
      // keyCode for '/' (slash)
      if (e.keyCode === 191) {
        const search = document.getElementById('search_input_react');
        search && search.focus();
      }
    });
  });
}();
