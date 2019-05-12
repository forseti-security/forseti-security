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

{% include docs/v2.14/deployment-prerequisites.md %}

### Setting up Cloud SQL

{% include docs/v2.14/setup-cloudsql.md %}

## Setting up a local environment

### Ubuntu setup

Install the necessary python dev tools and packages from
[apt_packages.txt](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/install/dependencies/apt_packages.txt).

### Mac setup

This guide is written for use with [Homebrew](https://brew.sh).

Use the following commands to install the necessary dependencies:

Install python-dev:

The system python that comes with OS X does not allow certain packages
(such as six) to be modified. Install brew’s version of python so that
separate python packages can be installed and managed.

  ```bash
  brew install python@2
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
[contributing guidelines](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/.github/CONTRIBUTING.md)
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

## Configuring Forseti settings

Before you run Forseti, you need to edit the `forseti_conf_server.yaml` file.
For more information, see [Configuring Forseti]({% link _docs/v2.14/configure/general/index.md %}).

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

To test the server is healthy and running, run the following command in
another terminal window
, and see if the server responds:

  ```bash
  forseti inventory list
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

Now attempt to make a virtual environment again.

------------------

If on Linux executing ``workon forseti-security``
results in ``bash: workon: command not found`` then
ensure ``workon`` is in the source path. Try fixing
source path issue by executing the following:

``source /usr/local/bin/virtualenvwrapper.sh``

and then trying ``workon forseti-security`` again.

You can also put these into your bash profile:

  ```bash
  export WORKON_HOME=$HOME/.virtualenvs
  source /usr/local/bin/virtualenvwrapper.sh
  ```
 
------------------

If on Linux executing ``python setup.py install``
results in ``EnvironmentError: mysql_config not found`` then
try the following:

``sudo apt install default-libmysqlclient-dev``

------------------

If on OS X executing ``python setup.py install``
results in ``my_config.h`` not found, then try the following:

  [source](https://stackoverflow.com/a/51483898)
  ```bash
  brew install mysql

  brew unlink mysql

  brew install mysql-connector-c

  sed -i -e 's/libs="$libs -l "/libs="$libs -lmysqlclient -lssl -lcrypto"/g' /usr/local/bin/mysql_config

  pip install MySQL-python

  brew unlink mysql-connector-c

  brew link --overwrite mysql
  
  ```

------------------

If running the server results in this error:
```
ImportError: No module named forseti.common.util

```

Try to add a symlink from the source code to the virtual environment:

```bash
cd <virtual environment>/lib/python2.7/site-packages/google/cloud

ln -s <path to your git source code>/google/cloud/forseti forseti
```

------------------


## What's next

* To learn about more CLI commands, see [Use]({% link _docs/v2.14/use/index.md %}).
