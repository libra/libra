const { isWebUri } = require('valid-url');
const path = require('path');

const getDarkModeImage = img => `img/${path.parse(img).name}-dark${path.parse(img).ext}`;

const category = (label, items) => {
  return {
    customProps: {iconClasses: ['listTitle']},
    label,
    type: 'category',
    items
  };
};

const backToHome = {
  customProps: {
    classNames: ['backToHome'],
    icon: 'img/shared/arrow-left.svg',
    iconHover: 'img/shared/arrow-left-hover.svg',
    iconDarkHover: 'img/shared/arrow-left-dark-hover.svg',
  },
  href: '/docs/welcome-to-diem',
  label: 'Home',
  type: 'link',
};

const categoryBoilerplate = (id, image) => {
  const imageUrl = typeof image === 'string' ? image : image.url;
  const imageType = typeof image === 'string' ? 'svg' : image.type;

  return [
    backToHome,
    {
      customProps: {
        classNames: ['categoryLabel'],
        icon: `img/${imageUrl}.${imageType}`,
        iconDark: `img/${imageUrl}-dark.${imageType}`,
        noLink: true,
      },
      id,
      type: 'doc',
    },
    {
      customProps: standaloneLinkClasses(),
      href: `/docs/${id}`,
      label: 'Overview',
      type: 'link',
    },
  ];
};

const getReference = (theme = 'secondary') => {
  const defaultType = theme === 'primary' ? 'doc' : 'ref';
  const standaloneReferenceLink = id => ({
    customProps: {
      classNames: ['standaloneReferenceLink'],
    },
    id,
    type: defaultType,
  });
  const referenceLink = ({id, icon, iconDark, withinCategory = false}) => ({
    type: withinCategory ? 'ref' : defaultType,
    id,
    customProps: {
      classNames: ['iconIndented'],
      icon,
      iconDark: iconDark ? iconDark : getDarkModeImage(icon),
    }
  });

  return [
    {
      customProps: {
        classNames: [
          theme === 'secondary' && 'referenceVerticalSpacing',
        ],
      },
      type: 'category',
      label: 'Tools',
      items: [
        referenceLink({
          id: 'sdks/overview',
          icon: 'img/sdks.svg',
        }),
        referenceLink({
          id: 'cli',
          icon: 'img/cli.svg',
        }),
        referenceLink({
          id: 'github/overview',
          icon: 'img/github.svg',
        }),
        referenceLink({
          id: 'reference-docs/overview',
          icon: 'img/reference-documentation.svg',
        }),
      ],
    },
    {
      type: 'category',
      label: 'Learning Center',
      items: [
        referenceLink({
          id: 'tutorials/overview',
          icon: 'img/cog.png',
          withinCategory: true,
        }),
        referenceLink({
          id: 'wallet-app/public-demo-wallet',
          icon: 'img/overlapping-circle-and-square-2.svg',
          iconDark: 'img/overlapping-circle-and-square-dark.svg',
          withinCategory: true,
        }),
        referenceLink({
          id: 'merchant/try-demo-merchant',
          icon: 'img/bobby-pin-2.svg',
          iconDark: 'img/bobby-pin-dark.svg',
          withinCategory: true,
        }),
        referenceLink({
          id: 'technical-papers/overview',
          icon: 'img/document.svg',
          withinCategory: true,
        }),
      ],
    },
    standaloneReferenceLink('reference/security'),
    standaloneReferenceLink('reference/glossary'),
  ];
};

const standaloneLink = (link, label) =>
  isWebUri(link) || link === ''
    ? {
        customProps: standaloneLinkClasses(),
        href: link,
        label,
        type: 'link',
      }
    : {
        customProps: standaloneLinkClasses(),
        id: link,
        type: 'doc',
      };

const standaloneLinkClasses = () => {
  return {
    classNames: ['categoryIndex']
  };
};

module.exports = {
  category,
  backToHome,
  categoryBoilerplate,
  getReference,
  standaloneLink,
};
