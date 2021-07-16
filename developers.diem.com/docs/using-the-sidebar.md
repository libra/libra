---
id: using-the-sidebar
title: Using the Sidebar
---

## An example of a basic sidebar

Let's break this down by parts:

```
[
  ...categoryBoilerplate('core/overview', 'core-contributors'),
  standaloneLink('merchant/merchant-guide'),
  category('Concepts', [
    'core/diem-protocol',
    'core/nodes',
    'core/life-of-a-transaction',
  ]),
  category('Tutorials', [
    'core/my-first-transaction',
    'core/my-first-client',
  ]),
  getReference(),
];
```

### CategoryBoilerplate

```
...categoryBoilerplate('core/overview', 'core-contributors'),
```

This gives you the back to home button, the label for the category, and an overview link, which is the category homepage.

The first parameter, `core/overview`, specifies where the overview lives,

The second parameter, `core-contributors`, specifies where the image lives.

#### Possible Edge Case
We assume that the image is an svg, but if it's not you can pass in an object instead of a string. So let's say the image was a png, `core-contributors.png`. Instead of

`...categoryBoilerplate('core/overview', 'core-contributors')`

you could pass in

`...categoryBoilerplate('core/overview', { url: 'core-contributors', type: 'png' })`

### StandaloneLink
`standaloneLink('merchant/merchant-guide')`

A standalone link is just a link that is not within any category. It can either be a doc link or an external link. The helper function can impliciltly tell which it is. If it is an external link it might look like this

`standaloneLink('https://www.google.com', 'Google')`

### Category
```
category('Concepts', [
  'core/diem-protocol',
  'core/nodes',
  'core/life-of-a-transaction',
]),
```
The first parameter, `Concepts`, is the label for the category

The second parameter is the items within that category. You can have subcategories, here is one example.

```
category('Diem Reference Wallet', [
    category('Concepts', [
      'wallet-app/intro-to-drw',
      'wallet-app/diem-coin-sourcing',
    ]),
    category('Tutorials', [
      'wallet-app/public-demo-wallet',
      category('Test the Diem Reference Wallet', [
          'wallet-app/try-local-web-wallet',
          'wallet-app/try-local-mobile-wallet',
      ]),
      'wallet-app/set-up-for-development'
    ]),
  ]),
```
This even has a sub-sub category

## Editing the home sidebar

When it comes to the home sidebar and the reference section, I assume these will be touched much less so I have not built helper classes for them. The main thing to know about the home sidebar is that the links have to be done slightly differently. Here is an example:
```
{
  type: 'ref',
  id: 'sdks/overview',
  extra: {
    classNames: ['iconIndented'],
    icon: 'img/cog.png',
    iconDark: 'img/cog-dark.png',
  },
},
```
Really what I would do if you want to add a link is just copy and paste this, replace the id with the doc you want, and replace the images with the one you want


## Other Tips

* Unlike when editing docs, when editing the sidebar you have to restart the server to have your changes reflected
