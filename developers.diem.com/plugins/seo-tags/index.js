module.exports = function (context, options) {
  return {
    name: 'seo-tags',
    injectHtmlTags() {
      return {
        headTags: [
          {
            tagName: 'meta',
            attributes: {
              name: 'google-site-verification',
              content: 'N41HlOqnlgd2AyjlubZKx9YpXFYT5mOF0UzaiuAiHP4',
            },
          },
          {
            tagName: 'meta',
            attributes: {
              name: 'yandex-verification',
              content: '406584314ef6edd3',
            },
          },
        ],
      };
    },
  };
};
