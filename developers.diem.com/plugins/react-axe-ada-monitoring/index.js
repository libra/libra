var webpack = require("webpack");

module.exports = function (context, options) {
  return {
    name: 'react-axe-ada-monitoring',
    description: `
      This plugin allows an environment variable to be
      passed to the frontend via webpack. The specific
      relevance is that we only want to enable ada checking
      in a develop environment
    `,
    configureWebpack(config, isServer, utils) {
      return {
        plugins: [
          new webpack.DefinePlugin({
            TEST_ADA: process.env.TEST_ADA,
          })
        ],
      };
    },
  };
};
