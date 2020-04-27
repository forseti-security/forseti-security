---
title: Run Website Locally
order: 003
---

#  {{ page.title }}

The instructions below are aimed at developers using Linux, particularly Debian
or Ubuntu. This page shows you how to install and run the website server
locally, so that you can test your documentation changes before merging.

---

## High-Level Overview

To build the Forseti Security website locally:

1. [Install Docker](#install-docker)
2. [Install Ruby & RubyGems](#install-ruby)
3. [Install Website Build Dependencies](#install-web-deps)
4. [Install Bundler](#install-bundler)
5. [Install Jekyll](#install-jekyll)
6. [Fetch, Build, and Run Forseti Web Code](#fetch-code)

## Step by Step Instructions

### Install Docker {#install-docker}

```bash
sudo apt-get update
sudo apt-get install docker-ce
```

NOTE: If Docker is not available in the repository, follow
the steps [here from the Docker
website](https://docs.docker.com/install/linux/docker-ce/ubuntu/#set-up-the-repository)
to add Docker to the package index.

NOTE: If the previous command fails even after ensuring that Docker
is in the package repository list, you may need to clear your
docker lib (rm -rf /var/lib/docker) as well. Doing this will delete
all images on disk. Ensure that they are backed up somewhere
if you don't want this to happen.

In order to avoid permission issues later on, add your user to the
``docker`` group:

```bash
sudo adduser $USER docker
```

Before continuing, test that Docker is running correctly by
doing the following:

```bash
docker run hello-world
```

### Install Ruby & RubyGems {#install-ruby}

To install Ruby and RubyGems, execute the following:

```bash
sudo apt-get install ruby ruby-dev
```

### Install Website Build Dependencies {#install-web-deps}

In order to build the website code in the last step, you will need a
few Linux dependencies installed.

To add these dependencies, run the following:

```bash
sudo apt-get install imagemagick libmagickwand-dev zlib1g-dev
```

### Install Bundler {#install-bundler}

```bash
gem install bundler
```

You may encounter the following error:

```bash
ERROR:  While executing gem ... (Gem::FilePermissionError)
You don't have write permissions for the /var/lib/gems/2.3.0 directory.
```

If you do, you can setup a Ruby virtual environment
like [RVM](http://rvm.io/) or [rbenv](https://github.com/rbenv/rbenv).
If you do not want to setup a virtual environment,
follow the steps documented [here](https://stackoverflow.com/a/47207118/1783829)
 which are listed below:

```bash
cd /var/lib
sudo chmod -R a+w gems/
```

If you get the error again with ``You don't have write permissions for the
/var/lib/bin`` the solution is listed below:

```bash
cd /usr/local/
sudo chmod -R a+w gems/
```

### Install Jekyll {#install-jekyll}

Install Jekyll by executing the following command:

```bash
gem install jekyll
```

If you run into the following error

```bash
ERROR: Error installing jekyll:
ERROR: Failed to build gem native extension.
...
mkmf.rb can't find header files for ruby at /usr/lib/ruby/include/ruby.h
```

the root issue is that Jekyll has dependencies with Ruby on Linux that are
not installed by default such as ``ruby-dev``. This should not happen
if you installed [Ruby per above](#install-ruby).

Additional context [here](https://github.com/jekyll/jekyll-help/issues/209).

To install these additional dependencies, you need to execute the following:

```bash
sudo apt-get install ruby ruby-dev
```

With the dependencies now present, try installing Jekyll again:

```bash
gem install jekyll
```

### Fetch, Build, and Run Forseti Web Code

#### Fetch Code
Create a folder for the Forseti website and pull down the code.

```bash
mkdir forseti-web
cd forseti-web/
user@host:~/forseti-web$ git init
user@host:~/forseti-web$ git remote add origin https://github.com/forseti-security/forseti-security.git
user@host:~/forseti-web$ git pull origin forsetisecurity.org-dev
```

#### Build Website

Build the Forseti website:

```bash
user@host:~/forseti-web$ bundle install
```

#### Serve the Website locally

To launch and run the website locally, run:

```bash
user@host:~/forseti-web$ bundle exec jekyll serve
```
