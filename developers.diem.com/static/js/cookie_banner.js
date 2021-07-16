document.addEventListener('DOMContentLoaded', function(event) {
  const cookieKey = 'diem-developer-website.cookies-accepted';
  const cookiesAccepted = localStorage.getItem(cookieKey);
  const cookieBanner = document.getElementById('cookie-banner');

  if (!cookiesAccepted) {
    cookieBanner.style.display = 'block';
    cookieBanner.classList.add('visible');
    document.body.classList.add('cookie-banner-open');
  } else {
    cookieBanner.style.display = 'none';
  }

  document.getElementById('cookie-banner-close').addEventListener('click', function() {
    localStorage.setItem(cookieKey, true);
    cookieBanner.classList.add('closed');
    document.body.classList.remove('cookie-banner-open');

    window.setTimeout(function(){
      cookieBanner.style.display = 'none';
    }, 200);
  });
});
