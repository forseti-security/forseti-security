# Preqrequisites to installing locally
### Enable APIs in Google Cloud Platform
1. Google Cloud Resource Manager
2. Google Cloud SQL
3. Google Cloud SQL API

### Create Cloud SQL Instance
1. Create a new instance in the [SQL page of GCP console](https://console.cloud.google.com/sql).
    * Select second generation.
    * Specify Instance ID.
    * Select MySQL 5.7 version.
    * Select db-n1-standard-1 machine type.
    * Select 25GB storage capacity.
    * Select High Availability (HA) mode.  If you skip the failover replica id, a default one will be provided.
    * Fill in other details, as desired.
    * Click Create button.
2. Configure Users Access Control
    * Change password for root user.
    * Create a new user with [read/write privileges](https://cloud.google.com/sql/docs/mysql/users?hl=en_US#privileges).
3. Create New Database
    * Enter a name.
4. Follow these instructions to establish a secure connection using [SQL Proxy](https://cloud.google.com/sql/docs/mysql-connect-proxy#connecting_mysql_client)
## Protobuf compiler (`protoc`)
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

## MySql software
The MySql python connector requires `mysql_config` to be present in your system.

### On Ubuntu
```sh
$ sudo apt-get install libmysqlclient-dev
```
Note: If libmysqlclient-dev doesn't install mysql_config, then try also installing mysql_server.

### On OS X
The easiest way to do this is with [Homebrew](https://brew.sh):
```sh
$ brew install mysql
```

## pip and virtualenvwrapper (suggested)
### Ubuntu
```sh
$ sudo apt-get install python-pip
$ sudo pip install --upgrade virtualenvwrapper
```

### OS X
Make sure you have the XCode commandline tools installed. Then install
virtualenvwrapper:

```sh
$ xcode-select --install
$ sudo pip install --upgrade virtualenvwrapper
```
After installing, [run a couple of initialization steps](https://virtualenvwrapper.readthedocs.io/en/latest/)
to export the WORKON_HOME env and source the virtualenvwrapper.sh.
