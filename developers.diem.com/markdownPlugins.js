const remarkableKatex = require('remarkable-katex');

module.exports = [
  function enableKatex(md) {
    md.use(remarkableKatex);
  },

  /**
   * Enable some defaults on the Markdown class
   */
  function enableInlineRuler(md) {
    md.inline.ruler.enable([
      'sub',
      'sup'
    ]);
  },

  function addEmDash(md) {
    const rule = (textRule) => (tokens, idx, options, env) => {
      const text = textRule(tokens, idx, options, env);
      return text.replace('---', ' &mdash; ');
    };
    md.renderer.rules.text = rule(md.renderer.rules.text);
  },
  /**
   * This will add a class to an image. To use structure as:
   *   [<title>](<img path){: .<class>}
   *
   * Example - add "download" class to an image:
   *   [PDF](assets/illustrations/move-language-pdf.png){: .download}
   */
  function addImageClass(md) {
    // This takes a render method in as an arg.
    const rule = (imageRule) => (tokens, idx, options, env) => {
      // Get the default image
      const img = imageRule(tokens, idx, options, env);

      const clsTkn = tokens[idx+1];
      // The token we are looking for will be text with content
      if (!clsTkn || clsTkn.type !== 'text' || !clsTkn.content) {
        return img;
      }

      //Finds the "{: .<className>}" and pulls out the className only
      const getClassName = (name) => {
        return name.match(/\{\:\s*\.[\w-]*\s*\}/g)
          ? name.match(/(\w|\-)+/g)
          : '';
      }

      const classString = ` class="${getClassName(clsTkn.content)}">`;
      // Remove the special token or it will get rendered
      clsTkn.content = '';

      return img.slice(0, -1) + classString;
    };

    md.renderer.rules.image = rule(md.renderer.rules.image);
  }
];
