---
title: Testing
order: 105
---
# {{ page.title }}

This page describes how to run tests on your Forseti contributions. You need to
install Forseti before you run the unit tests, either by following the
[Developer Setup]({% link _docs/latest/develop/dev/setup.md %}) (a local installation) 
or the [GCP setup]({% link _docs/latest/configure/general/index.md %}) 
(install on a GCE instance; you will need to connect to that instance to run the unit tests).

---

## Executing tests

You can find unit tests in the top-level `tests/` directory. We use
[`unittest`](https://docs.python.org/2/library/unittest.html) from standard Python to run our tests.

Before you run unit tests and pylint checkers, make sure you have
[Docker CE](https://docs.docker.com/install/) installed.


**Run the following commands in the _top-level_ directory of Forseti.**

Install Forseti in a docker image:

  ```bash
  ./install/scripts/docker_install_forseti.sh
  ```

Run all the unit tests:

  ```bash
  ./install/scripts/docker_unittest_forseti.sh
  ```

Run pylint checkers:

  ```bash
  ./install/scripts/docker_pylint_forseti.sh
  ```
