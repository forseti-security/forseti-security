---
title: Development
order: 001
hide:
  left_sidebar: true
---
# {{ page.title }}

## Contributing

We welcome your contributions! Before you start, please review our
[contributing guidelines](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/.github/CONTRIBUTING.md).

## Testing

This page describes how to run tests on your Forseti contributions.

### Unit tests

You can find unit tests in the top-level `tests/` directory.

To execute all the unit tests, run the command below:

  ```bash
  $ python -m unittest discover -s . -p "*_test*"
  ```

To execute the tests just for a particular file pattern:

  ```bash
  $ python -m unittest discover -s . -p "*some_feature_test*"
  ```
