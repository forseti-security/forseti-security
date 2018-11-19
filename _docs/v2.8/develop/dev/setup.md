---
title: Setup
order: 101
---
#  {{ page.title }}

This page explains how to set up Forseti for local development.

---

## Before you begin

To complete this guide, you will need:

* A Github account.
* A Google Cloud Platform (GCP) organization.
* A GCP project for Forseti with billing enabled.
* The ability to assign roles on your organization's Cloud Identity
  and Access Management (Cloud IAM) policy.
* The ability to assign G Suite domain-wide delegation to the Forseti service account.

## Setting up GCP infrastructure

{% include docs/v2.8/deployment-prerequisites.md %}

### Setting up Cloud SQL

{% include docs/v2.8/setup-cloudsql.md %}

## Setting up a local environment

### Ubuntu setup

Install the necessary python dev tools and packages from
[apt_packages.txt](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/install/dependencies/apt_packages.txt).

### Mac setup

This guide is written for use with [Homebrew](https://brew.sh).

Use the following commands to install the necessary dependencies:

Install python-dev:

  ```bash
  brew install python
  ```

Install openssl:

  ```bash
  brew install openssl
  ```

Install mysql_config:

  ```bash
  brew install mysql
  ```

## Creating a virtualenv

Ensure virtualenv is installed in your system. Virtualenv allows you to
create multiple environments to contain different modules and dependencies
in different projects:

  ```bash
  sudo pip install virtualenv
  ```

Use the following command to create a virtualenv:

  ```bash
  # create a virtualenv
  mkvirtualenv forseti-security

  workon forseti-security
  ```

## Getting the source code

Follow our
[contributing guidelines](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/.github/CONTRIBUTING.md)
to create a fork of the Forseti code, and learn how to submit a pull request (PR).

## Installing build dependencies

Use the following command to install required build dependencies:

  ```bash
  pip install -q --upgrade -r forseti-security/requirements.txt
  ```

## Running the Python setup

Use the following commands to navigate to your cloned repository and run the Python setup:

  ```bash
  cd forseti-security

  python setup.py install
  ```

## Troubleshooting

If you are installing on Mac OS X with [Homebrew](https://brew.sh/) and get
a fatal error related to `'openssl/opensslv.h' file not found`, you might need to
export `CPPFLAGS` and `LDFLAGS` for the openssl package. For more information,
see [issue 3489](https://github.com/pyca/cryptography/issues/3489).

To find the `CPPFLAGS` and `LDFLAGS` information and export them, run the
following command:

  ```bash
  brew info openssl

    ... lots of information ...

    There aren't usually any consequences of this for you. If you build your
    own software and it requires this formula, you'll need to add to your
    build variables:

    LDFLAGS:  -L/SOME/PATH/TO/openssl/lib
    CPPFLAGS: -I/SOME/PATH/TO/openssl/include
  ```

Next, copy the `LDFLAGS` and `CPPFLAGS` values and export them, similar to the
following:

  ```bash
  export CPPFLAGS=-I/SOME/PATH/TO/openssl/include

  export LDFLAGS=-L/SOME/PATH/TO/openssl/lib
  ```

In the above example, `/SOME/PATH/TO` represents the path specific to your
system. Make sure to use the values from your terminal.

------------------

If on Linux executing ``mkvirtualenv forseti-security`` results in
``bash: mkvirtualenv: command not found`` then try the following:

``sudo pip install virtualenv virtualenvwrapper``

Now attempt to make a virtual environent again.

------------------

If on Linux executing ``python setup.py install``
results in ``EnvironmentError: mysql_config not found`` then
try the following:

``sudo apt install default-libmysqlclient-dev``

------------------

If on Linux executing ``workon forseti-security``
results in ``bash: workon: command not found`` then
ensure ``workon`` is in the source path. Try fixing
source path issue by executing the following:

``source /usr/local/bin/virtualenvwrapper.sh``

and then trying ``workon forseti-security`` again.

## Configuring Forseti settings

Before you run Forseti, you need to edit the forseti configuration file.
For more information, see [Configuring Forseti]({% link _docs/v2.8/configure/general/index.md %}).

## Starting Forseti

After you complete the above steps, you should be able to run the Forseti
server and the command-line interface (CLI) client:

  ```bash
  forseti_server \
  --endpoint "localhost:50051" \
  --forseti_db "mysql://root@127.0.0.1:3306/forseti_security" \
  --services scanner model inventory explain notifier \
  --config_file_path "PATH_TO_YOUR_CONFIG.yaml" \
  --log_level=info \
  --enable_console_log
  ```

For more information about commands, run the following in
another terminal window:

  ```bash
  forseti -h or --help
  ```

## What's next

* To learn about more CLI commands, see [Use]({% link _docs/v2.8/use/index.md %}).
