# Forseti Security
* [Installation](#installation)
  *  [Prerequisites](#prerequisites)
  *  [Setup](#setup)
* [Execution](#execution)
* [Tests](#tests)
* [Forseti Security modules](#forseti-security-modules)

## Installation
### Prerequisites
#### Python version
Forseti Security currently works with Python 2.7.

#### `gcloud` tool
Download and install [gcloud](https://cloud.google.com/sdk/gcloud/) tool. If you already have
it installed, it's recommended to update it to the latest version.

```sh
$ gcloud components update
```

#### Protobuf compiler (`protoc`)
Download the [protoc pre-built
binary](https://github.com/google/protobuf/releases). Forseti Security has been tested with
the protoc 3.0+ (the zip file is named something like
`protoc-VERSION-OS-ARCH.zip`). It's recommended to use an updated version of
protoc (e.g. 3.2.0 fixed a lot of bugs).

Unzip the file and copy the `protoc` binary from the extracted`bin/` directory
to somewhere like /usr/local/bin (or somewhere similar on your path). If `which
protoc` doesn't bring up anything, you may need to change the permissions of the
binary to be executable, i.e. `chmod 755 /path/to/protoc`.

```sh
$ mkdir ~/Downloads/protoc-3.2
$ cd ~/Downloads/protoc-3.2
$ wget https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-osx-x86_64.zip
$ unzip protoc-3.2.0-osx-x86_64.zip
$ sudo cp bin/protoc /usr/local/bin/protoc
$ sudo chmod 755 /usr/local/bin/protoc
```

#### MySql software
The MySql python connector requires `mysql_config` to be present in your system.

##### Ubuntu
```sh
$ sudo apt-get install libmysqlclient-dev
```
Note: If libmysqlclient-dev doesn't install mysql_config, then try also installing mysql_server.

##### OS X
[Homebrew](https://brew.sh) is required.
```sh
$ brew install mysql
```

#### pip and virtualenvwrapper (suggested)
##### Ubuntu
```sh
$ sudo apt-get install python-pip
$ sudo pip install --upgrade virtualenvwrapper
```

##### OS X
Make sure you have the XCode commandline tools installed. Then install
virtualenvwrapper:

```sh
$ xcode-select --install
$ sudo pip install --upgrade virtualenvwrapper
```
After installing, [run a couple of initialization steps](https://virtualenvwrapper.readthedocs.io/en/latest/)
to export the WORKON_HOME env and source the virtualenvwrapper.sh.

#### SendGrid API Key
SendGrid is the email service provider.  To use it, you simply need
to [create a General API Key with SendGrid](https://sendgrid.com/docs/User_Guide/Settings/api_keys.html)
and pass it as a template or flag value.

### Setup
#### Create a virtualenv and activate it, e.g.:
```sh
$ mkvirtualenv forseti-security
$ workon forseti-security
```

#### Run the python setup:
Navigate to your cloned repo.
```sh
$ python setup.py install
```

#### Install Service Account Key
1. Create a custom service account in the [GCP console](https://console.cloud.google.com/iam-admin/serviceaccounts).
Having a custom service account with only the IAM permissions needed
for testing would allow you to delete the service account when you are done,
and delete the key when it is no longer needed. Unlike your user account
which can be phished, or the default service account which is harder to
clean up.
[Best practices for service accounts.](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#best_practices)
2. Permission the service account with the following IAM policy:
    * Project Editor
    * Cloud SQL Editor 
3. Create and download the json key to your local environment.
4. Configure the [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials)
to env variable to reference this key.
```sh
$ export GOOGLE_APPLICATION_CREDENTIALS="<path to your service account key>"
```

## Execution
You should now be able to run the following commandline tools. To see the flag options for each, use
the `--helpshort` or `--helpfull` flags.

 - `forseti_inventory` ([README](/google/cloud/security/inventory/README.md))
 - `forseti_scanner` ([README](/google/cloud/security/scanner/README.md))
 - `forseti_enforcer` ([README](/google/cloud/security/enforcer/README.md))

## Tests
There are unit tests in the `tests/` directory. To execute them, run:

```sh
$ python setup.py google_test --test-dir <test dir>
```

## Forseti Security modules
The Forseti Security modules are developed as modules under `google.cloud.security`.
Each module has its own classes that encapsulate the tool's core functionality.
There are also runner scripts that execute the tool.

### Adding new modules
To add a new module, create it in this directory. Once you have a runner script
that works, create a runner function in the `stubs.py` and plug it into the setup.py
`entry_points['console_scripts']` dictionary.

Re-run `python setup.py install` to install the new console script.
