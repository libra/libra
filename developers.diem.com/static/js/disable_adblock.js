// Turn off ESLint for this file because it's sent down to users as-is.
/* eslint-disable */
!function(){
  document.addEventListener('DOMContentLoaded', (event) => {
    const refreshBtn = document.getElementById('disable-adblock-refresh')
    if (refreshBtn) {
      refreshBtn.addEventListener('click', function() {
        location.reload();
      });
    }
  });
}();
