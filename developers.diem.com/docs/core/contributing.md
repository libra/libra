---
id: contributing
title: Contribution Guide
---

Our goal is to make contributing to the Diem project easy and transparent.

<blockquote className="block_note">
The Diem Core project is currently an early-stage prototype, it is undergoing rapid development. Before making any substantial contribution to the project, be sure to discuss it in the Discourse forum to ensure that it fits into the project roadmap.
</blockquote>

## Contributor License Agreement

The Diem project follows many popular Open Source projects by requiring a signed CLA before accepting contributions. [Sign the CLA](https://diem.com/cla-sign/).

## Contributing to Diem Core

To contribute to Diem Core, ensure that you have the latest version of the codebase. To setup Diem Core with all the necessary dependencies for linting, testing, and building the documentation, run the following:
```
$ git clone https://github.com/diem/diem.git
$ cd diem
$ ./scripts/dev_setup.sh
$ source ~/.cargo/env
$ cargo build
$ cargo xtest
```

## Coding Guidelines

For detailed guidance on how to contribute to the Diem Core codebase refer to [Coding Guidelines](coding-guidelines.md).

## Documentation

All developer documentation is published on the Diem developer site. The developer site is open source, and the code for building the site is located in this [repository](https://github.com/diem/website/). The developer site is built using [Docusaurus](https://docusaurus.io/).

If you are familiar with Markdown, you can start contributing!

## Pull Requests

To submit your pull request:

1. Fork the `diem` repo and create your branch from `master`.
2. If you have added code that should be tested, add unit tests.
3. If you have made changes to APIs, update the relevant documentation, and build and test the developer site.
4. Verify and ensure that the test suite passes.
5. Make sure your code passes both linters.
6. Complete the Contributor License Agreement (CLA), if you haven't already done so.
7. Submit your pull request.

## Code of Conduct
Please refer to the [Code of Conduct](../policies/code-of-conduct.md), which describes the expectations for interactions within the community.

## Issues

Diem uses [GitHub issues](https://github.com/diem/diem/issues) to track bugs. Please include necessary information and instructions to reproduce your issue. Security-related bugs should be reported using our [security procedures](/reference/security.md).
