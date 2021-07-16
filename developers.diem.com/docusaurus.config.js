const darkCodeTheme = require('prism-react-renderer/themes/palenight');
const lightCodeTheme = require('prism-react-renderer/themes/github');
const objectAssignDeep = require('object-assign-deep');
const universalConfig = require('@libra-opensource/diem-docusaurus-components/src/universal-config');

module.exports = objectAssignDeep(universalConfig, {
  title: 'Diem Documentation',
  onBrokenLinks: 'ignore',
  tagline: 'The Diem Association’s mission is to enable a simple global payment system and financial infrastructure that empowers billions of people.',
  url: 'https://developers.diem.com',
  baseUrl: '/',
  favicon: 'img/shared/favicon.ico',
  organizationName: 'Diem',
  projectName: 'Diem',
  themeConfig: {
    algolia: {
      apiKey: 'f0c9dd5d95535c4b0d99aa1fbcb0e949',
      indexName: 'diem_developer_website',
    },
    image: "/img/shared/share-logo.jpg",
    prism: {
      darkTheme: darkCodeTheme,
      theme: lightCodeTheme,
      additionalLanguages: ['java'],
    },
    sidebarCollapsible: false,
    siteID: 'developers',
  },
  plugins: [
    require.resolve('./plugins/webpack'),
    require.resolve('./plugins/react-axe-ada-monitoring'),
    require.resolve('./plugins/seo-tags'),
    [
      '@docusaurus/plugin-client-redirects',
      {
        createRedirects: function (existingPath) {
          if (existingPath && existingPath.includes('/overview')) {
            return [
              existingPath.replace('/overview', '')
            ];
          }
        },
      },
    ],
    require.resolve(
      '@libra-opensource/diem-docusaurus-components/src/plugin-segment',
    ),
  ],
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars'),
          // Please change this to your repo.
          editUrl: 'https://github.com/diem/diem/edit/main/developers.diem.com/',
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          editUrl:
            'https://github.com/diem/diem/edit/main/developers.diem.com/blog/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
  customFields: {
    navbar: {
      title: 'Diem Documentation',
    },
    segment: {
      productionKey: 'Llc3xSsbfceDLVBzwOJKoJSkSHMRoj8V',
      stagingKey: '4o1O3LLd7EvFJ2Cp3CbFfXk3yy8LeT5t',
    },
    trackingCookieConsent: 'diem-docs-cookies-allowed',
    trackingCookieExpiration: 90, // in days
  },
});
