(function() {
  let isMainNavClick = false;
  let isSubNavClick = false;
  document.addEventListener('DOMContentLoaded', function() {
    addClickHandlersToMainNavTriggers();
    addClickHandlersToSubNavTriggers();
  });

  function addClickHandlersToMainNavTriggers() {
    const mainNavToggles = document.querySelectorAll('.main-nav .mobile.main-nav-trigger');
    const mainNav = document.querySelector('.main-nav .navigationWrapper.navigationSlider');
    window.addEventListener('click', function() {
      if (!isMainNavClick) {
        closeNav(mainNav, mainNavToggles);
      }
      isMainNavClick = false;
    });
    mainNav.addEventListener('click', function(event) {
      event.stopPropagation();
    });
    addClickHandlersToNavToggles(mainNavToggles, mainNav, true, false);
  }

  function addClickHandlersToSubNavTriggers() {
    const subNavToggles = document.querySelectorAll('#SubNav .mobile.sub-nav-trigger');
    const subNav = document.querySelector('#SubNav  .navigationWrapper.navigationSlider');
    window.addEventListener('click', function() {
      if (!isSubNavClick) {
        closeNav(subNav, subNavToggles);
      }
      isSubNavClick = false;
    });
    subNav.addEventListener('click', function(event) {
      event.stopPropagation();
    });
    addClickHandlersToNavToggles(subNavToggles, subNav, false, true);
  }

  function addClickHandlersToNavToggles(navToggles, nav, _isMainNavClick, _isSubNavClick) {
    navToggles.forEach(function(node) {
      node.addEventListener('click', function() {
        isMainNavClick = _isMainNavClick;
        isSubNavClick = _isSubNavClick;
        navToggles.forEach(function(toggle) {
          toggleVisibility(toggle);
          toggle.classList.contains('trigger-open');
        });
        toggleVisibility(nav);
      });
    });
  }

  function toggleVisibility(node) {
    node.classList.toggle('mobile-hidden');
  }

  function closeNav(nav, navToggles) {
    navToggles.forEach(function(toggle) {
      if (toggle.classList.contains('trigger-open')) {
        toggle.classList.remove('mobile-hidden');
      } else {
        toggle.classList.add('mobile-hidden');
      }
    });
    nav.classList.add('mobile-hidden');
  }
})();
