# Forseti Security

Forseti Security provides tools to monitor your Google Cloud Platform
environment. These are the currently available services:

* Inventory - caches resource data for use by other tools.
* Scanner - scans GCP resource policies for violations.
* Enforcer - fixes policy violations found from the scanner.


# Setup

### Install the protobuf compiler.

Download the [protoc pre-built
binary](https://github.com/google/protobuf/releases). This has been tested with
the 3.2.0 version of protoc (the zip file is named something like
`protoc-VERSION-OS-ARCH.zip`). It's recommended to use an updated version of
protoc (e.g. 3.2.0 fixed a lot of bugs).

Unzip the file and copy the `protoc` binary from the extracted`bin/` directory
to somewhere like /usr/local/bin (or somewhere similar on your path). If `which
protoc` doesn't bring up anything, you may need to change the permissions of the
binary to be executable, i.e. `chmod 755 /path/to/protoc`.

### Install MySql-related software.

The MySql python connector requires `mysql_config` to be present in your system.

*Ubuntu*

```sh
$ sudo apt-get install mysql-server
```

*OS X*

```sh
$ brew install mysql
```

### Install pip and virtualenvwrapper if you haven't already (suggested):

*Ubuntu*

```sh
$ sudo apt-get install python-pip
$ pip install --upgrade virtualenvwrapper
```

*OS X*

Make sure you have the XCode commandline tools installed. Then install
virtualenvwrapper:

```sh
$ xcode-select --install
$ pip install --upgrade virtualenvwrapper
```

### Create a virtualenv, e.g.:

```sh
$ mkvirtualenv forseti-security
```

### Activate the virtualenv you just created, then run the python setup:

```sh
$ workon forseti-security
$ python setup.py install
```

### Set the `FORSETI_SECURITY_HOME` environment variable
The setup script will add a line in the virtualenv postactivate script to export
a variable, `FORSETI_SECURITY_HOME`. Reactivate your virtualenv to export the
environment variable or copy-paste the one-liner at the end of the setup.py.

```sh
$ workon forseti-security
```


# Configuration
In the `config` directory, there are sample configuration files. Make a copy of
these and remove the `.sample` extension.

Refer to the specific Forseti tools' READMEs for more information on
configuration.


# Running the tools

You should now be able to run the following commandline scripts:

 - `cloud_inventory` ([README](google/cloud/security/inventory/README.md))
 - `cloud_scanner` ([README](google/cloud/security/scanner/README.md))
 - `cloud_enforcer` ([README](google/cloud/security/enforcer/README.md))


# Tests
There are unit tests in the `tests/` directory. To execute them, run:

```sh
$ python setup.py google_test --test-dir <test dir>
```


# Disclaimer
This is not an official Google product.
